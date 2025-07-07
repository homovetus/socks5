{-# LANGUAGE OverloadedStrings #-}

-- | Functions to start connection using SOCKS5 proxy.
module Network.SOCKS5.Client
  ( ClientConfig (..),

    -- * SOCKS5
    runTCPConnect,
    runTCPBind,
    runUDPAssociate,

    -- * SOCKS5 with TLS
    runTCPConnectTLS,
    runTCPBindTLS,
    runUDPAssociateTLS,
  )
where

import Control.Exception
import Control.Monad.State
import Data.Binary (Binary, decode)
import Data.ByteString qualified as B
import Data.Text.Lazy qualified as LT
import Network.Run.TCP
import Network.Run.UDP
import Network.SOCKS5.Internal
import Network.Socket
import Network.Socket.ByteString qualified as SB
import Network.TLS
import Text.Read (readMaybe)

data ClientConfig = ClientConfig
  { -- | Hostname or IP address of the SOCKS5 proxy server
    proxyHost :: HostName,
    -- | Port number of the SOCKS5 proxy server
    proxyPort :: ServiceName,
    -- | List of authentication methods to use, only NoAuth and UserPass are supported
    auth :: [Method],
    -- | Username and password for UserPass authentication
    userPass :: Maybe (LT.Text, LT.Text)
  }

type StateIO a = StateT B.ByteString IO a

-- | Run a TCP connection to target address and port through proxy.
runTCPConnect ::
  -- | Destination address
  Address ->
  -- | Destination port
  ServiceName ->
  -- | Proxy configuration
  ClientConfig ->
  -- | Client function to run with the connected socket
  (Socket -> IO a) ->
  IO a
runTCPConnect destAddr destPort config client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    startConnect destAddr destPort config sock client

-- | Run a TCP connection to target address and port through proxy with TLS.
runTCPConnectTLS ::
  -- | Destination address
  Address ->
  -- | Destination port
  ServiceName ->
  -- | Proxy configuration
  ClientConfig ->
  -- | TLS parameters for the connection
  ClientParams ->
  -- | Client function to run with the connected TLS context
  (Context -> IO a) ->
  IO a
runTCPConnectTLS destAddr destPort config params client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    ctx <- contextNew sock params
    handshake ctx
    res <- startConnect destAddr destPort config ctx client
    bye ctx
    return res

startConnect ::
  (Connection c) =>
  Address ->
  ServiceName ->
  ClientConfig ->
  c ->
  (c -> IO a) ->
  IO a
startConnect destAddr destPort config conn client =
  flip evalStateT B.empty $ do
    performAuth config conn
    portNum <- resolvePort destPort
    encodeAndSend conn $ Request Connect destAddr portNum
    reply <- recv' conn
    case reply of
      Reply Succeeded _ _ -> liftIO $ client conn
      _ -> liftIO $ throwIO $ HandshakeFail reply

-- | run a TCP connection to target by making proxy listen on a port and bind to it.
runTCPBind ::
  -- | Destination address
  Address ->
  -- | Destination port
  ServiceName ->
  -- | Proxy configuration
  ClientConfig ->
  -- | Function to call when the bind is successful, receives the proxy's listening address and port
  (Address -> PortNumber -> IO ()) ->
  -- | Client function to run with the bound socket, receives the connected peer's address and port
  (Address -> PortNumber -> Socket -> IO a) ->
  IO a
runTCPBind destAddr destPort config notify client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    startBind destAddr destPort config sock notify client

-- | run a TCP connection to target by making proxy listen on a port and bind to it with TLS.
runTCPBindTLS ::
  -- | Destination address
  Address ->
  -- | Destination port
  ServiceName ->
  -- | Proxy configuration
  ClientConfig ->
  -- | TLS parameters for the connection
  ClientParams ->
  -- | Function to call when the bind is successful, receives the proxy's listening address and port
  (Address -> PortNumber -> IO ()) ->
  -- | Client function to run with the bound TLS context, receives the connected peer's address and port
  (Address -> PortNumber -> Context -> IO a) ->
  IO a
runTCPBindTLS destAddr destPort config params notify client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    ctx <- contextNew sock params
    handshake ctx
    res <- startBind destAddr destPort config ctx notify client
    bye ctx
    return res

startBind ::
  (Connection c) =>
  Address ->
  ServiceName ->
  ClientConfig ->
  c ->
  (Address -> PortNumber -> IO ()) ->
  (Address -> PortNumber -> c -> IO a) ->
  IO a
startBind destAddr destPort config conn notify client =
  flip evalStateT B.empty $ do
    performAuth config conn
    portNum <- resolvePort destPort
    encodeAndSend conn $ Request Bind destAddr portNum
    reply1 <- recv' conn
    case reply1 of
      Reply Succeeded listenAddr listenPort -> do
        liftIO $ notify listenAddr listenPort
        reply2 <- recv' conn
        case reply2 of
          Reply Succeeded hostAddr hostPort ->
            liftIO $ client hostAddr hostPort conn
          _ -> liftIO $ throwIO $ HandshakeFail reply2
      _ -> liftIO $ throwIO $ HandshakeFail reply1

-- | Start a UDP relay on proxy server and run a client function with the connected UDP socket.
runUDPAssociate ::
  -- | Proxy configuration
  ClientConfig ->
  -- | Client function to run with the connected UDP socket, receives a function to send data and a function to receive data
  ((B.ByteString -> SockAddr -> IO ()) -> IO (B.ByteString, SockAddr) -> IO a) ->
  IO a
runUDPAssociate config client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sockTCP -> do
    startUDPAssociate config sockTCP client

-- | Start a UDP relay on proxy server with TLS and run a client function with the connected UDP socket. Note that the UDP socket is not encrypted, only the initial connection to the proxy is secured.
runUDPAssociateTLS ::
  -- | Proxy configuration
  ClientConfig ->
  -- | TLS parameters for the connection
  ClientParams ->
  -- | Client function to run with the connected UDP socket, receives a function to send data and a function to receive data
  ((B.ByteString -> SockAddr -> IO ()) -> IO (B.ByteString, SockAddr) -> IO a) ->
  IO a
runUDPAssociateTLS config params client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sockTCP -> do
    ctx <- contextNew sockTCP params
    handshake ctx
    res <- startUDPAssociate config ctx client
    bye ctx
    return res

startUDPAssociate ::
  (Connection c) =>
  ClientConfig ->
  c ->
  ((B.ByteString -> SockAddr -> IO ()) -> IO (B.ByteString, SockAddr) -> IO a) ->
  IO a
startUDPAssociate config conn client =
  flip evalStateT B.empty $ do
    performAuth config conn
    encodeAndSend conn $ Request UDPAssociate (AddressIPv4 "0.0.0.0") 0
    reply <- recv' conn
    case reply of
      Reply Succeeded relayAddr relayPort -> liftIO $ do
        runUDPClient (show relayAddr) (show relayPort) $ \sockUDP proxySockAddr -> do
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
      _ -> liftIO $ throwIO $ HandshakeFail reply

performAuth :: (Connection c) => ClientConfig -> c -> StateIO ()
performAuth config conn = do
  encodeAndSend conn $ Hello $ auth config
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

resolvePort :: ServiceName -> StateIO PortNumber
resolvePort port = liftIO $
  case readMaybe port of
    Just p -> return p
    Nothing -> throwIO $ PortStringInvalid port

recv' :: (Binary b, Connection c) => c -> StateIO b
recv' conn = do
  buffer <- get
  (val, left) <- recvAndDecode conn buffer
  put left
  return val
