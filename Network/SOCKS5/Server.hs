{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SOCKS5.Server
  ( runSOCKS5Server,
  )
where

import Control.Concurrent.Async
import Control.Exception
import Control.Monad
import Data.Bifunctor
import Data.Binary
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as LB
import Data.IORef
import Data.List.NonEmpty qualified as NE
import Network.Run.TCP
import Network.SOCKS5.Internal
import Network.Socket
import Network.Socket.ByteString qualified as SB
import System.IO.Error

runSOCKS5Server :: HostName -> ServiceName -> IO ()
runSOCKS5Server host port = do
  putStrLn $ "Starting SOCKS5 server on " ++ host ++ ":" ++ port
  runTCPServer (Just host) port $ \sockTCP -> do
    clientAddr <- getPeerName sockTCP
    putStrLn $ "Accepted new client connection from " ++ show clientAddr
    handle (\(e :: SomeException) -> putStrLn $ show clientAddr ++ ": " ++ show e) $ newClient sockTCP

newClient :: Socket -> IO ()
newClient clientSock = do
  auths <- NE.fromList . methods <$> recvHello clientSock
  unless (NoAuth `elem` auths) $ throwIO NoAcceptableAuthMethods
  sendMethodSelection clientSock NoAuth
  req <- recvRequest clientSock
  putStrLn $ "Received SOCKS5 Request: " ++ show req
  case command req of
    Connect -> handleConnect req clientSock
    Bind -> handleBind req clientSock
    UDPAssociate -> handleUDPAssociate req clientSock

handleConnect :: Request -> Socket -> IO ()
handleConnect (Request _ addr port) clientSock =
  handle (replyError clientSock) $ runTCPClient (show addr) (show port) $ \destSock -> do
    putStrLn "Successfully connected to destination server."
    (selfAddr, selfPort) <- fromSockAddr_ <$> getSocketName clientSock
    sendReply clientSock Succeeded selfAddr selfPort
    putStrLn $ "Sent SOCKS5 Reply: Succeeded, bound to " ++ show selfAddr ++ ":" ++ show selfPort
    let forwardToDest = do
          clientData <- SB.recv clientSock 4096
          unless (B.null clientData) $ do
            SB.sendAll destSock clientData
            forwardToDest
    let forwardToClient = do
          serverData <- SB.recv destSock 4096
          unless (B.null serverData) $ do
            SB.sendAll clientSock serverData
            forwardToClient
    concurrently_ forwardToDest forwardToClient
    putStrLn "Data forwarding complete. Closing dest connection."
    close destSock

handleBind :: Request -> Socket -> IO ()
handleBind (Request _ _destAddr _destPort) clientSock =
  handle (replyError clientSock) $ bracket (newTCPSocket "0.0.0.0") close $ \listenSock -> do
    (selfAddr, _) <- fromSockAddr_ <$> getSocketName clientSock
    (_, listenPort) <- fromSockAddr_ <$> getSocketName listenSock
    putStrLn $ "Listening for connections on " ++ show selfAddr ++ ":" ++ show listenPort
    sendReply clientSock Succeeded selfAddr listenPort
    (destSock, (destAddr, destPort)) <- second fromSockAddr_ <$> accept listenSock
    putStrLn $ "Accepted connection from " ++ show destAddr ++ ":" ++ show destPort
    sendReply clientSock Succeeded destAddr destPort
    let forwardToDest = do
          clientData <- SB.recv clientSock 4096
          unless (B.null clientData) $ do
            SB.sendAll destSock clientData
            forwardToDest
    let forwardToClient = do
          serverData <- SB.recv destSock 4096
          unless (B.null serverData) $ do
            SB.sendAll clientSock serverData
            forwardToClient
    concurrently_ forwardToDest forwardToClient
    putStrLn "Data forwarding complete. Closing dest connection."
    close destSock
    close listenSock
  where
    newTCPSocket host = do
      addrInfo <- head <$> getAddrInfo (Just defaultHints {addrFlags = [AI_PASSIVE], addrSocketType = Stream}) (Just host) (Just "0")
      sock <- openSocket addrInfo
      bind sock (addrAddress addrInfo)
      listen sock 1
      return sock

-- The UDP relay server MUST acquire from the SOCKS server the expected
-- IP address of the client that will send datagrams to the BND.PORT
-- given in the reply to UDP ASSOCIATE.  It MUST drop any datagrams
-- arriving from any source IP address other than the one recorded for
-- the particular association.

handleUDPAssociate :: Request -> Socket -> IO ()
handleUDPAssociate (Request _ destAddr destPort) clientSock =
  handle (replyError clientSock) $ bracket (newUDPSocket "0.0.0.0") close $ \relaySock -> do
    (selfAddr, _) <- fromSockAddr_ <$> getSocketName clientSock
    (_, relayPort) <- fromSockAddr_ <$> getSocketName relaySock
    sendReply clientSock Succeeded selfAddr relayPort
    (expectedClient, _) <- fromSockAddr_ <$> getPeerName clientSock
    putStrLn $ "UDP association created for " ++ show expectedClient ++ ". Relaying on port " ++ show relayPort ++ "."
    -- If the client is not in possesion of the information at the time of the UDP
    -- ASSOCIATE, the client MUST use a port number and address of all zeros.
    let expectedDest = case (destAddr, destPort) of
          (AddressIPv4 "0.0.0.0", 0) -> Nothing
          (AddressIPv6 "::", 0) -> Nothing
          (AddressDomain _, _) -> Nothing
          _ -> Just destAddr
    -- A UDP association terminates when the TCP connection that the UDP ASSOCIATE request arrived on terminates.
    withAsync (forwardUDP expectedClient expectedDest relaySock) $ \_ -> do
      putStrLn "UDP association active. Waiting for TCP control connection to close."
      waitForTCPClose clientSock
    putStrLn "TCP control connection closed. Terminating UDP association."
  where
    newUDPSocket host = do
      addrInfo <- head <$> getAddrInfo (Just defaultHints {addrFlags = [AI_PASSIVE], addrSocketType = Datagram}) (Just host) (Just "0")
      sock <- openSocket addrInfo
      bind sock (addrAddress addrInfo)
      return sock
    waitForTCPClose sock = do
      chunk <- SB.recv sock 1024
      unless (B.null chunk) $ waitForTCPClose sock

forwardUDP :: Address -> Maybe Address -> Socket -> IO ()
forwardUDP expectedClientAddr expectedDestAddr relaySock = do
  putStrLn $ "Waiting UDP packets from client: " ++ show expectedClientAddr ++ " and dest: " ++ show expectedDestAddr
  -- Use an IORef to store the client address once received, we don't know port yet
  clientUDPSockAddr <- newIORef Nothing
  forever $ do
    (datagram, sourceUDPSockAddr) <- first LB.fromStrict <$> SB.recvFrom relaySock 8192
    let (sourceUDPAddr, _) = fromSockAddr_ sourceUDPSockAddr
    -- sourceUDPAddr is used to compare only the address, not the port
    mClientSockAddr <- readIORef clientUDPSockAddr
    case mClientSockAddr of
      Nothing ->
        when (sourceUDPAddr == expectedClientAddr) $ do
          putStrLn $ "Accepted first UDP packet from client at " ++ show sourceUDPSockAddr
          writeIORef clientUDPSockAddr (Just sourceUDPSockAddr)
          handleClientPacket datagram
      Just clientSockAddr ->
        if
          | sourceUDPSockAddr == clientSockAddr -> handleClientPacket datagram
          | isExpectedDest sourceUDPAddr -> handleRemotePacket datagram sourceUDPSockAddr clientSockAddr
          | otherwise -> putStrLn $ "Received packet from unexpected source: " ++ show sourceUDPSockAddr
  where
    handleClientPacket datagram = do
      let (UDPRequest _ addr port load) = decode datagram :: UDPRequest
      destAddr <- NE.head <$> getAddrInfo (Just defaultHints {addrSocketType = Datagram}) (Just $ show addr) (Just $ show port)
      SB.sendAllTo relaySock (LB.toStrict load) (addrAddress destAddr)
    isExpectedDest addr = case expectedDestAddr of
      Nothing -> True
      Just destAddr -> addr == destAddr
    handleRemotePacket datagram sourceSockAddr clientSockAddr = do
      let (remoteAddr, remotePort) = fromSockAddr_ sourceSockAddr
      sendUDPRequestTo relaySock 0 remoteAddr remotePort datagram clientSockAddr

replyError :: Socket -> SomeException -> IO ()
replyError sock e = do
  let rep = case fromException e of
        Just (ioe :: IOException) ->
          if
            | isDoesNotExistError ioe -> HostUnreachable
            | isPermissionError ioe -> ConnectionNotAllowedByRuleset
            | otherwise -> GeneralSOCKSFailure
        _ -> GeneralSOCKSFailure
  putStrLn $ "Replying with error: " ++ show rep
  sendReply sock rep (AddressIPv4 "0.0.0.0") 0
  throwIO e
