{-# LANGUAGE OverloadedStrings #-}

module Network.SOCKS5.Client
  ( ClientConfig (..),
    SOCKSException (..),
    runTCPConnect,
    runTCPConnectTLS,
    runTCPBind,
    runTCPBindTLS,
    runUDPAssociate,
    runUDPAssociateTLS,
  )
where

import Control.Exception
import Control.Monad.State
import Data.Binary (Binary, decode)
import Data.ByteString qualified as B
import Network.Run.TCP
import Network.Run.UDP
import Network.SOCKS5.Internal
import Network.Socket
import Network.Socket.ByteString qualified as SB
import Network.TLS
import Text.Read (readMaybe)

data ClientConfig = ClientConfig
  { proxyHost :: HostName,
    proxyPort :: ServiceName,
    auth :: Method
  }

type StateIO a = StateT B.ByteString IO a

runTCPConnect ::
  Address ->
  ServiceName ->
  ClientConfig ->
  (Socket -> IO a) ->
  IO a
runTCPConnect destAddr destPort config client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    startConnect destAddr destPort config sock client

runTCPConnectTLS ::
  Address ->
  ServiceName ->
  ClientConfig ->
  ClientParams ->
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
    reply <- recvS conn
    case reply of
      Reply Succeeded _ _ -> liftIO $ client conn
      _ -> liftIO $ throwIO $ HandshakeFail reply

runTCPBind ::
  Address ->
  ServiceName ->
  ClientConfig ->
  (Address -> PortNumber -> IO ()) ->
  (Address -> PortNumber -> Socket -> IO a) ->
  IO a
runTCPBind destAddr destPort config notify client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    startBind destAddr destPort config sock notify client

runTCPBindTLS ::
  Address ->
  ServiceName ->
  ClientConfig ->
  ClientParams ->
  (Address -> PortNumber -> IO ()) ->
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
    reply1 <- recvS conn
    case reply1 of
      Reply Succeeded listenAddr listenPort -> do
        liftIO $ notify listenAddr listenPort
        reply2 <- recvS conn
        case reply2 of
          Reply Succeeded hostAddr hostPort ->
            liftIO $ client hostAddr hostPort conn
          _ -> liftIO $ throwIO $ HandshakeFail reply2
      _ -> liftIO $ throwIO $ HandshakeFail reply1

runUDPAssociate ::
  ClientConfig ->
  ((B.ByteString -> SockAddr -> IO ()) -> IO (B.ByteString, SockAddr) -> IO a) ->
  IO a
runUDPAssociate config client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sockTCP -> do
    startUDPAssociate config sockTCP client

runUDPAssociateTLS ::
  ClientConfig ->
  ClientParams ->
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
    reply <- recvS conn
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
  encodeAndSend conn $ Hello [auth config]
  selectedMethod <- recvS conn
  case method selectedMethod of
    NoAuth -> return ()
    _ -> liftIO $ throwIO $ AuthUnsupported (method selectedMethod)

resolvePort :: ServiceName -> StateIO PortNumber
resolvePort port = liftIO $
  case readMaybe port of
    Just p -> return p
    Nothing -> throwIO $ PortStringInvalid port

recvS :: (Binary b, Connection c) => c -> StateIO b
recvS conn = do
  buffer <- get
  (val, left) <- recvAndDecode conn buffer
  put left
  return val
