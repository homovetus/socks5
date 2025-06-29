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
import Data.Binary
import Data.ByteString qualified as B
import Network.Run.TCP
import Network.Run.UDP
import Network.SOCKS5.Internal
import Network.Socket
import Network.Socket.ByteString qualified as SB
import Text.Read

data ClientConfig = ClientConfig
  { proxyHost :: HostName,
    proxyPort :: ServiceName,
    auth :: Method
  }

runTCPConnect :: ClientConfig -> Address -> ServiceName -> (Socket -> IO a) -> IO a
runTCPConnect config destAddr destPort client = do
  portNum <- resolvePort destPort
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    performAuth config sock
    sendRequest sock Connect destAddr portNum
    reply <- recvReply sock
    case reply of
      Reply Succeeded _ _ -> client sock
      _ -> throwIO $ HandshakeFail reply

runTCPBind ::
  ClientConfig ->
  Address ->
  ServiceName ->
  (Address -> PortNumber -> IO ()) ->
  (Address -> PortNumber -> Socket -> IO a) ->
  IO a
runTCPBind config destAddr destPort notify client = do
  portNum <- resolvePort destPort
  runTCPClient (proxyHost config) (proxyPort config) $ \sock -> do
    performAuth config sock
    sendRequest sock Bind destAddr portNum
    reply1 <- recvReply sock
    case reply1 of
      Reply Succeeded listenAddr listenPort -> do
        notify listenAddr listenPort
        reply2 <- recvReply sock
        case reply2 of
          Reply Succeeded hostAddr hostPort ->
            client hostAddr hostPort sock
          _ -> throwIO $ HandshakeFail reply2
      _ -> throwIO $ HandshakeFail reply1

runUDPAssociate :: ClientConfig -> ((B.ByteString -> SockAddr -> IO ()) -> IO (B.ByteString, SockAddr) -> IO a) -> IO a
runUDPAssociate config client = do
  runTCPClient (proxyHost config) (proxyPort config) $ \sockTCP -> do
    performAuth config sockTCP
    sendRequest sockTCP UDPAssociate (AddressIPv4 "0.0.0.0") 0
    reply <- recvReply sockTCP
    case reply of
      Reply Succeeded relayAddr relayPort -> do
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
      _ -> throwIO $ HandshakeFail reply

resolvePort :: ServiceName -> IO PortNumber
resolvePort port = case readMaybe port of
  Just p -> return p
  Nothing -> throwIO $ PortStringInvalid port

performAuth :: ClientConfig -> Socket -> IO ()
performAuth config sock = do
  sendHello sock [auth config]
  selectedMethod <- recvMethodSelection sock
  case method selectedMethod of
    NoAuth -> return ()
    _ -> throwIO $ AuthUnsupported (method selectedMethod)
