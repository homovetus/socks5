{-# LANGUAGE OverloadedStrings #-}

-- |
-- This module provides a client for the SOCKS5 proxy protocol
-- It offers two tiers of functions:
--
-- * High-level 'run...' functions: These are "all-in-one" helpers that
--     manage the entire connection, from connecting to the proxy to running
--     your client code.
--
-- * Low-level 'exec...' functions: These functions execute a single SOCKS5
--     command on an already established connection. They provide more control
--     for users who need to manage the connection to the proxy manually.
--
-- = Example Usage
-- Here is a minimal example of how to use the library to connect to a remote server through a SOCKS5 proxy:
--
-- > {-# LANGUAGE OverloadedStrings #-}
-- >
-- > import qualified Data.ByteString.Char8 as C8
-- > import Network.SOCKS5.Client
-- > import Network.Socket.ByteString (recv, sendAll)
-- >
-- > main :: IO ()
-- > main = do
-- >   let proxyConfig =
-- >         ClientConfig
-- >           { proxyHost = "127.0.0.1",
-- >             proxyPort = "11451",
-- >             userPass = Nothing
-- >           }
-- >
-- >   runTCPConnect "example.com" 80 proxyConfig $ \sock -> do
-- >     putStrLn "Connected to example.com through SOCKS5 proxy!"
-- >     sendAll sock "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
-- >     response <- recv sock 4096
-- >     C8.putStrLn response
module Network.SOCKS5.Client
  ( ClientConfig (..),

    -- * High-level functions
    runTCPConnect,
    runTCPBind,
    runUDPAssociate,

    -- * High-level functions with TLS
    runTCPConnectTLS,
    runTCPBindTLS,
    runUDPAssociateTLS,

    -- * Low-level functions
    execConnect,
    execBind,
    execUDPAssociate,
  )
where

import Control.Exception
import Control.Monad.State
import Data.Binary (Binary, decode)
import Data.ByteString qualified as B
import Data.IP
import Data.Text.Lazy qualified as LT
import Network.Run.TCP
import Network.Run.UDP
import Network.SOCKS5.Internal
import Network.Socket
import Network.Socket.ByteString qualified as SB
import Network.TLS
import Text.Read (readMaybe)

-- | Configuration for connecting to the SOCKS5 proxy server.
data ClientConfig = ClientConfig
  { -- | Hostname or IP address of the SOCKS5 proxy server.
    proxyHost :: HostName,
    -- | Port number of the SOCKS5 proxy server.
    proxyPort :: ServiceName,
    -- | Credentials for authentication. 'Nothing' defaults to the 'NoAuth' method.
    -- Otherwise 'UserPass' will be used with the provided value.
    userPass :: Maybe (LT.Text, LT.Text)
  }

type StateIO a = StateT B.ByteString IO a

-- | Establishes a TCP connection to a target through a SOCKS5 proxy using the CONNECT command.
runTCPConnect ::
  -- | Target hostname or IP address.
  HostName ->
  -- | Target port.
  PortNumber ->
  -- | SOCKS5 proxy configuration.
  ClientConfig ->
  -- | The action to run with the connected 'Socket'.
  (Socket -> IO a) ->
  IO a
runTCPConnect destHost destPort config client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    execConnect destHost destPort config sock
    client sock

-- | Establishes a TLS-secured TCP connection to a target through a SOCKS5 proxy using the CONNECT command.
runTCPConnectTLS ::
  HostName ->
  PortNumber ->
  ClientConfig ->
  -- | TLS parameters for the connection.
  ClientParams ->
  -- | The action to run with the TLS 'Context'.
  (Context -> IO a) ->
  IO a
runTCPConnectTLS destHost destPort config params client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    ctx <- contextNew sock params
    handshake ctx
    execConnect destHost destPort config ctx
    res <- client ctx
    bye ctx
    return res

-- | Executes the CONNECT command on an established connection to the proxy.
-- This function only performs the SOCKS5 negotiation.
execConnect ::
  (Connection c) =>
  -- | Target hostname or IP address.
  HostName ->
  -- | Target port.
  PortNumber ->
  -- | SOCKS5 proxy configuration.
  ClientConfig ->
  -- | An existing connection to the proxy (e.g., a 'Socket' or 'Context').
  c ->
  IO ()
execConnect destHost destPort config conn =
  flip evalStateT B.empty $ do
    performAuth config conn
    let destAddr = hostToAddress destHost
    encodeAndSend conn $ Request Connect destAddr destPort
    reply <- recv' conn
    case reply of
      Reply Succeeded _ _ -> return ()
      _ -> liftIO $ throwIO $ HandshakeFail reply

-- | Asks the SOCKS5 proxy to BIND to a port and waits for an incoming connection.
-- This is for protocols that require the client to accept a connection, like FTP.
runTCPBind ::
  -- | The hostname or IP address the proxy should connect to (often ignored).
  HostName ->
  -- | The port the proxy should connect to (often ignored).
  PortNumber ->
  ClientConfig ->
  -- | An action called after the proxy successfully binds, providing the listening address and port.
  (HostName -> PortNumber -> IO ()) ->
  -- | The action to run with the 'Socket' once a peer connects, providing the peer's address and port.
  (HostName -> PortNumber -> Socket -> IO a) ->
  IO a
runTCPBind destHost destPort config notify client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    (hostAddr, hostPort) <- execBind destHost destPort config sock notify
    client hostAddr hostPort sock

-- | Asks the SOCKS5 proxy to BIND over a TLS-secured connection.
runTCPBindTLS ::
  HostName ->
  PortNumber ->
  ClientConfig ->
  ClientParams ->
  -- | An action called after the proxy successfully binds, providing the listening address and port.
  (HostName -> PortNumber -> IO ()) ->
  -- | The action to run with the 'Context' once a peer connects, providing the peer's address and port.
  (HostName -> PortNumber -> Context -> IO a) ->
  IO a
runTCPBindTLS destHost destPort config params notify client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    ctx <- contextNew sock params
    handshake ctx
    (hostAddr, hostPort) <- execBind destHost destPort config ctx notify
    res <- client hostAddr hostPort ctx
    bye ctx
    return res

-- | Executes the BIND command on an established connection.
-- This function handles the two-stage reply from the proxy.
execBind ::
  (Connection c) =>
  -- | The hostname or IP address the proxy should connect to (often ignored).
  HostName ->
  -- | The port the proxy should connect to (often ignored).
  PortNumber ->
  -- | SOCKS5 proxy configuration.
  ClientConfig ->
  -- | An existing connection to the proxy (e.g., a 'Socket' or 'Context').
  c ->
  -- | An action called after the proxy successfully binds.
  (HostName -> PortNumber -> IO ()) ->
  -- | Returns the hostname/IP and port of the connecting peer.
  IO (HostName, PortNumber)
execBind destHost destPort config conn notify =
  flip evalStateT B.empty $ do
    performAuth config conn
    let destAddr = hostToAddress destHost
    encodeAndSend conn $ Request Bind destAddr destPort
    reply1 <- recv' conn
    case reply1 of
      Reply Succeeded listenAddr listenPort -> do
        liftIO $ notify (show listenAddr) listenPort
        reply2 <- recv' conn
        case reply2 of
          Reply Succeeded hostAddr hostPort ->
            return (show hostAddr, hostPort)
          _ -> liftIO $ throwIO $ HandshakeFail reply2
      _ -> liftIO $ throwIO $ HandshakeFail reply1

-- | Establishes a UDP ASSOCIATION with the SOCKS5 proxy, enabling UDP traffic to be relayed.
runUDPAssociate ::
  ClientConfig ->
  -- | Action to run with the connected UDP socket, providing function to send and receive datagrams.
  ((B.ByteString -> SockAddr -> IO ()) -> IO (B.ByteString, SockAddr) -> IO a) ->
  IO a
runUDPAssociate config client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sockTCP -> do
    (relayHost, relayPort) <- execUDPAssociate config sockTCP
    runUDPClient relayHost (show relayPort) $ \sockUDP proxySockAddr -> do
      let sendDataTo :: B.ByteString -> SockAddr -> IO ()
          sendDataTo userData destination = do
            let (dstAddr, dstPort) = fromSockAddr_ destination
            sendUDPRequestTo sockUDP 0 dstAddr dstPort (B.fromStrict userData) proxySockAddr
          recvDataFrom :: IO (B.ByteString, SockAddr)
          recvDataFrom = do
            (datagram, _) <- SB.recvFrom sockUDP 8192
            let udpReply = decode (B.fromStrict datagram) :: UDPRequest
                originalSender = toSockAddr_ (address udpReply) (port udpReply)
            return (B.toStrict (payload udpReply), originalSender)
      client sendDataTo recvDataFrom

-- | Establishes a UDP association over a TLS-secured control connection.
-- Note: The control connection to the proxy is secured with TLS, but the resulting
-- UDP traffic is not encrypted.
runUDPAssociateTLS ::
  ClientConfig ->
  ClientParams ->
  -- | Action to run with the connected UDP socket, providing function to send and receive datagrams.
  ((B.ByteString -> SockAddr -> IO ()) -> IO (B.ByteString, SockAddr) -> IO a) ->
  IO a
runUDPAssociateTLS config params client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sockTCP -> do
    ctx <- contextNew sockTCP params
    handshake ctx
    (relayHost, relayPort) <- execUDPAssociate config ctx
    res <- runUDPClient relayHost (show relayPort) $ \sockUDP proxySockAddr -> do
      let sendDataTo :: B.ByteString -> SockAddr -> IO ()
          sendDataTo userData destination = do
            let (dstAddr, dstPort) = fromSockAddr_ destination
            sendUDPRequestTo sockUDP 0 dstAddr dstPort (B.fromStrict userData) proxySockAddr
          recvDataFrom :: IO (B.ByteString, SockAddr)
          recvDataFrom = do
            (datagram, _) <- SB.recvFrom sockUDP 8192
            let udpReply = decode (B.fromStrict datagram) :: UDPRequest
                originalSender = toSockAddr_ (address udpReply) (port udpReply)
            return (B.toStrict (payload udpReply), originalSender)
      client sendDataTo recvDataFrom
    bye ctx
    return res

-- | Executes the UDP ASSOCIATE command on an established connection.
execUDPAssociate ::
  (Connection c) =>
  ClientConfig ->
  c ->
  -- | Returns the address and port of the UDP relay on the proxy server.
  IO (HostName, PortNumber)
execUDPAssociate config conn =
  flip evalStateT B.empty $ do
    performAuth config conn
    encodeAndSend conn $ Request UDPAssociate (AddressIPv4 "0.0.0.0") 0
    reply <- recv' conn
    case reply of
      Reply Succeeded relayAddr relayPort -> return (show relayAddr, relayPort)
      _ -> liftIO $ throwIO $ HandshakeFail reply

performAuth :: (Connection c) => ClientConfig -> c -> StateIO ()
performAuth config conn = do
  case userPass config of
    Nothing -> encodeAndSend conn $ Hello [NoAuth]
    Just _ -> encodeAndSend conn $ Hello [NoAuth, UserPass]
  selectedMethod <- recv' conn
  case method selectedMethod of
    NoAuth -> return ()
    UserPass -> do
      case userPass config of
        Just (user, pass) -> do
          encodeAndSend conn $ UserPassRequest user pass
          response <- recv' conn
          case response of
            UserPassResponse Success -> return ()
            UserPassResponse status -> liftIO $ throwIO $ AuthFailed status
        _ -> liftIO $ throwIO AuthMissingCredentials
    _ -> liftIO $ throwIO $ AuthUnsupported (method selectedMethod)

hostToAddress :: HostName -> Address
hostToAddress host = case readMaybe host :: Maybe IP of
  Just (IPv4 ipv4) -> AddressIPv4 ipv4
  Just (IPv6 ipv6) -> AddressIPv6 ipv6
  Nothing -> AddressDomain (LT.pack host)

recv' :: (Binary b, Connection c) => c -> StateIO b
recv' conn = do
  buffer <- get
  (val, left) <- recvAndDecode conn buffer
  put left
  return val
