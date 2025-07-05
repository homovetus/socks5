{-# LANGUAGE OverloadedStrings #-}

module Network.SOCKS5.Client
  ( ClientConfig (..),
    SOCKSException (..),
    runTCPBind,
    runTCPConnect,
    runUDPAssociate,
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
import Text.Read (readMaybe)

data ClientConfig = ClientConfig
  { proxyHost :: HostName,
    proxyPort :: ServiceName,
    auth :: Method
  }

type StateIO a = StateT B.ByteString IO a

runTCPConnect :: forall a. ClientConfig -> Address -> ServiceName -> (Socket -> IO a) -> IO a
runTCPConnect config destAddr destPort client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    evalStateT (startConnect sock) B.empty
  where
    startConnect :: Socket -> StateIO a
    startConnect sock = do
      performAuth config sock
      portNum <- liftIO $ resolvePort destPort
      liftIO $ sendRequest sock Connect destAddr portNum
      reply <- recvS sock
      case reply of
        Reply Succeeded _ _ -> liftIO $ client sock
        _ -> liftIO $ throwIO $ HandshakeFail reply

runTCPBind ::
  forall a.
  ClientConfig ->
  Address ->
  ServiceName ->
  (Address -> PortNumber -> IO ()) ->
  (Address -> PortNumber -> Socket -> IO a) ->
  IO a
runTCPBind config destAddr destPort notify client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    evalStateT (startBind sock) B.empty
  where
    startBind :: Socket -> StateIO a
    startBind sock = do
      performAuth config sock
      portNum <- liftIO $ resolvePort destPort
      liftIO $ sendRequest sock Bind destAddr portNum
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

runUDPAssociate :: forall a. ClientConfig -> ((B.ByteString -> SockAddr -> IO ()) -> IO (B.ByteString, SockAddr) -> IO a) -> IO a
runUDPAssociate config client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sockTCP -> do
    evalStateT (startUDPAssociate sockTCP) B.empty
  where
    startUDPAssociate :: Socket -> StateIO a
    startUDPAssociate sockTCP = do
      performAuth config sockTCP
      liftIO $ sendRequest sockTCP UDPAssociate (AddressIPv4 "0.0.0.0") 0
      reply <- recvS sockTCP
      case reply of
        Reply Succeeded relayAddr relayPort -> liftIO $ do
          runUDPClient (show relayAddr) (show relayPort) $ \sockUDP proxySockAddr -> do
            let sendDataTo :: B.ByteString -> SockAddr -> IO ()
                sendDataTo userData destination = do
                  let (dstAddr, dstPort) = fromSockAddr_ destination
                  sendUDPRequestTo sockUDP 0 dstAddr dstPort (B.fromStrict userData) proxySockAddr

                recvData :: IO (B.ByteString, SockAddr)
                recvData = do
                  (datagram, _) <- SB.recvFrom sockUDP 8192
                  let udpReply = decode (B.fromStrict datagram) :: UDPRequest
                      originalSender = toSockAddr_ (address udpReply) (port udpReply)
                  return (B.toStrict (payload udpReply), originalSender)

            client sendDataTo recvData
        _ -> liftIO $ throwIO $ HandshakeFail reply

resolvePort :: ServiceName -> IO PortNumber
resolvePort port = case readMaybe port of
  Just p -> return p
  Nothing -> throwIO $ PortStringInvalid port

performAuth :: ClientConfig -> Socket -> StateIO ()
performAuth config sock = do
  liftIO $ sendHello sock [auth config]
  selectedMethod <- recvS sock
  case method selectedMethod of
    NoAuth -> return ()
    _ -> liftIO $ throwIO $ AuthUnsupported (method selectedMethod)

recvS :: (Binary a) => Socket -> StateIO a
recvS sock = do
  buffer <- get
  (val, left) <- liftIO $ recvAndDecode sock buffer
  put left
  return val
