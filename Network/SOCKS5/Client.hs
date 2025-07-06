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

runTCPConnect :: forall a. Address -> ServiceName -> ClientConfig -> (Socket -> IO a) -> IO a
runTCPConnect destAddr destPort config client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    evalStateT (startConnect sock) B.empty
  where
    startConnect :: Socket -> StateIO a
    startConnect sock = do
      performAuth config sock
      portNum <- resolvePort destPort
      encodeAndSend sock $ Request Connect destAddr portNum
      reply <- recvS sock
      case reply of
        Reply Succeeded _ _ -> liftIO $ client sock
        _ -> liftIO $ throwIO $ HandshakeFail reply

runTCPConnectTLS :: forall a. ClientConfig -> Address -> ServiceName -> ClientParams -> (Context -> IO a) -> IO a
runTCPConnectTLS config destAddr destPort params client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    ctx <- contextNew sock params
    handshake ctx
    res <- evalStateT (startConnect ctx) B.empty
    bye ctx
    return res
  where
    startConnect :: Context -> StateIO a
    startConnect ctx = do
      performAuth config ctx
      portNum <- resolvePort destPort
      encodeAndSend ctx $ Request Connect destAddr portNum
      reply <- recvS ctx
      case reply of
        Reply Succeeded _ _ -> liftIO $ client ctx
        _ -> liftIO $ throwIO $ HandshakeFail reply

runTCPBind ::
  forall a.
  Address ->
  ServiceName ->
  ClientConfig ->
  (Address -> PortNumber -> IO ()) ->
  (Address -> PortNumber -> Socket -> IO a) ->
  IO a
runTCPBind destAddr destPort config notify client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    evalStateT (startBind sock) B.empty
  where
    startBind :: Socket -> StateIO a
    startBind sock = do
      performAuth config sock
      portNum <- resolvePort destPort
      encodeAndSend sock $ Request Bind destAddr portNum
      reply1 <- recvS sock
      case reply1 of
        Reply Succeeded listenAddr listenPort -> do
          liftIO $ notify listenAddr listenPort
          reply2 <- recvS sock
          case reply2 of
            Reply Succeeded hostAddr hostPort ->
              liftIO $ client hostAddr hostPort sock
            _ -> liftIO $ throwIO $ HandshakeFail reply2
        _ -> liftIO $ throwIO $ HandshakeFail reply1

runTCPBindTLS ::
  forall a.
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
    res <- evalStateT (startBind ctx) B.empty
    bye ctx
    return res
  where
    startBind :: Context -> StateIO a
    startBind ctx = do
      performAuth config ctx
      portNum <- resolvePort destPort
      encodeAndSend ctx $ Request Bind destAddr portNum
      reply1 <- recvS ctx
      case reply1 of
        Reply Succeeded listenAddr listenPort -> do
          liftIO $ notify listenAddr listenPort
          reply2 <- recvS ctx
          case reply2 of
            Reply Succeeded hostAddr hostPort ->
              liftIO $ client hostAddr hostPort ctx
            _ -> liftIO $ throwIO $ HandshakeFail reply2
        _ -> liftIO $ throwIO $ HandshakeFail reply1

runUDPAssociate :: forall a. ClientConfig -> ((B.ByteString -> SockAddr -> IO ()) -> IO (B.ByteString, SockAddr) -> IO a) -> IO a
runUDPAssociate config client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sockTCP -> do
    evalStateT (startUDPAssociate sockTCP) B.empty
  where
    startUDPAssociate :: Socket -> StateIO a
    startUDPAssociate sockTCP = do
      performAuth config sockTCP
      encodeAndSend sockTCP $ Request UDPAssociate (AddressIPv4 "0.0.0.0") 0
      reply <- recvS sockTCP
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

runUDPAssociateTLS :: forall a. ClientConfig -> ClientParams -> ((B.ByteString -> SockAddr -> IO ()) -> IO (B.ByteString, SockAddr) -> IO a) -> IO a
runUDPAssociateTLS config params client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sockTCP -> do
    ctx <- contextNew sockTCP params
    handshake ctx
    res <- evalStateT (startUDPAssociate ctx) B.empty
    bye ctx
    return res
  where
    startUDPAssociate :: Context -> StateIO a
    startUDPAssociate ctx = do
      performAuth config ctx
      encodeAndSend ctx $ Request UDPAssociate (AddressIPv4 "0.0.0.0") 0
      reply <- recvS ctx
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
