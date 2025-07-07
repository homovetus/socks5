{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Functions to run a SOCKS5 server.
module Network.SOCKS5.Server
  ( ServerConfig (..),

    -- * SOCKS5 Server
    runSOCKS5Server,

    -- * SOCKS5 Server with TLS
    runSOCKS5ServerTLS,
  )
where

import Control.Concurrent.Async
import Control.Exception
import Control.Monad
import Control.Monad.State
import Data.Bifunctor
import Data.Binary (Binary, decode)
import Data.ByteString qualified as B
import Data.IORef
import Data.List.NonEmpty qualified as NE
import Data.Text.Lazy qualified as LT
import Network.Run.TCP
import Network.SOCKS5.Internal
import Network.SOCKS5.Types
import Network.Socket
import Network.Socket.ByteString qualified as SB
import Network.TLS
import System.IO.Error

data ServerConfig = ServerConfig
  { -- | Hostname or IP address to bind the server to
    serverHost :: HostName,
    -- | Port number to listen on
    serverPort :: ServiceName,
    -- | List of User/Password pairs for UserPass authentication
    users :: [(LT.Text, LT.Text)]
  }

type StateIO a = StateT B.ByteString IO a

-- | Run a SOCKS5 server with the given configuration.
runSOCKS5Server :: ServerConfig -> IO ()
runSOCKS5Server config = do
  let host = serverHost config
      port = serverPort config
  putStrLn $ "Starting SOCKS5 server on " ++ host ++ ":" ++ port
  runTCPServer (Just host) port $ \sockTCP -> do
    clientAddr <- getPeerName sockTCP
    putStrLn $ "Accepted new client connection from " ++ show clientAddr
    handle (\(e :: SomeException) -> putStrLn $ show clientAddr ++ ": " ++ show e) $
      newClient config sockTCP sockTCP

-- | Run a SOCKS5 server with TLS support.
runSOCKS5ServerTLS :: ServerConfig -> ServerParams -> IO ()
runSOCKS5ServerTLS config params = do
  let host = serverHost config
      port = serverPort config
  putStrLn $ "Starting SOCKS5 server on " ++ host ++ ":" ++ port ++ " (TLS: on)"
  runTCPServer (Just host) port $ \sockTCP -> do
    clientAddr <- getPeerName sockTCP
    putStrLn $ "Accepted new client connection from " ++ show clientAddr
    handle (\(e :: SomeException) -> putStrLn $ show clientAddr ++ ": " ++ show e) $ do
      ctx <- contextNew sockTCP params
      handshake ctx
      newClient config ctx sockTCP
      bye ctx

newClient :: (Connection c) => ServerConfig -> c -> Socket -> IO ()
newClient config conn clientSock = do
  void $ flip runStateT B.empty $ do
    handleAuthentication config conn
    req <- recv' conn
    liftIO $ putStrLn $ "Received SOCKS5 Request: " ++ show req
    case command req of
      Connect -> liftIO $ handleConnect req conn clientSock
      Bind -> liftIO $ handleBind req conn clientSock
      UDPAssociate -> liftIO $ handleUDPAssociate req conn clientSock

handleAuthentication :: (Connection c) => ServerConfig -> c -> StateIO ()
handleAuthentication config conn = do
  auths <- methods <$> recv' conn
  let noUsers = null $ users config
  selectedMethod <-
    if
      | NoAuth `elem` auths && noUsers -> do
          encodeAndSend conn $ MethodSelection NoAuth
          return NoAuth
      | UserPass `elem` auths && not noUsers -> do
          encodeAndSend conn $ MethodSelection UserPass
          return UserPass
      | otherwise -> liftIO $ throwIO NoAcceptableAuthMethods
  when (selectedMethod == UserPass) $ do
    UserPassRequest uname passwd <- recv' conn
    let credentials = (uname, passwd)
    if credentials `elem` users config
      then encodeAndSend conn $ UserPassResponse Success
      else do
        encodeAndSend conn $ UserPassResponse Failure
        liftIO $ throwIO $ AuthFailed Failure

handleConnect :: (Connection c) => Request -> c -> Socket -> IO ()
handleConnect (Request _ addr port) conn clientSock = do
  handle (replyError conn) $
    runTCPClient (show addr) (show port) $ \destSock -> do
      putStrLn "Successfully connected to destination server."
      (selfAddr, selfPort) <- fromSockAddr_ <$> getSocketName clientSock
      encodeAndSend conn $ Reply Succeeded selfAddr selfPort
      putStrLn $ "Sent SOCKS5 Reply: Succeeded, bound to " ++ show selfAddr ++ ":" ++ show selfPort
      let forwardToDest = do
            clientData <- connRecv conn
            unless (B.null clientData) $ do
              SB.sendAll destSock clientData
              forwardToDest
      let forwardToClient = do
            serverData <- SB.recv destSock 4096
            unless (B.null serverData) $ do
              connSend conn $ B.fromStrict serverData
              forwardToClient
      concurrently_ forwardToDest forwardToClient
      putStrLn "Data forwarding complete. Closing dest connection."

handleBind :: (Connection c) => Request -> c -> Socket -> IO ()
handleBind (Request _ _destAddr _destPort) conn clientSock =
  handle (replyError conn) $
    bracket (newTCPSocket "0.0.0.0") close $ \listenSock -> do
      (selfAddr, _) <- fromSockAddr_ <$> getSocketName clientSock
      (_, listenPort) <- fromSockAddr_ <$> getSocketName listenSock
      putStrLn $ "Listening for connections on " ++ show selfAddr ++ ":" ++ show listenPort
      encodeAndSend conn $ Reply Succeeded selfAddr listenPort
      bracket (accept listenSock) (\(destSock, _) -> close destSock) $ \(destSock, destSockAddr) -> do
        let (destAddr, destPort) = fromSockAddr_ destSockAddr
        putStrLn $ "Accepted connection from " ++ show destAddr ++ ":" ++ show destPort
        encodeAndSend conn $ Reply Succeeded destAddr destPort
        let forwardToDest = do
              clientData <- connRecv conn
              unless (B.null clientData) $ do
                SB.sendAll destSock clientData
                forwardToDest
        let forwardToClient = do
              serverData <- SB.recv destSock 4096
              unless (B.null serverData) $ do
                connSend conn $ B.fromStrict serverData
                forwardToClient
        concurrently_ forwardToDest forwardToClient
        putStrLn "Data forwarding complete. Closing dest connection."
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

handleUDPAssociate :: (Connection c) => Request -> c -> Socket -> IO ()
handleUDPAssociate (Request _ destAddr destPort) conn clientSock =
  handle (replyError clientSock) $
    bracket (newUDPSocket "0.0.0.0") close $ \relaySock -> do
      (selfAddr, _) <- fromSockAddr_ <$> getSocketName clientSock
      (_, relayPort) <- fromSockAddr_ <$> getSocketName relaySock
      encodeAndSend conn $ Reply Succeeded selfAddr relayPort
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
    (datagram, sourceUDPSockAddr) <- first B.fromStrict <$> SB.recvFrom relaySock 8192
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
      SB.sendAllTo relaySock (B.toStrict load) (addrAddress destAddr)
    isExpectedDest addr = case expectedDestAddr of
      Nothing -> True
      Just destAddr -> addr == destAddr
    handleRemotePacket datagram sourceSockAddr clientSockAddr = do
      let (remoteAddr, remotePort) = fromSockAddr_ sourceSockAddr
      sendUDPRequestTo relaySock 0 remoteAddr remotePort datagram clientSockAddr

recv' :: (Binary b, Connection c) => c -> StateIO b
recv' conn = do
  buffer <- get
  (val, left) <- liftIO $ recvAndDecode conn buffer
  put left
  return val

replyError :: (Connection c) => c -> SomeException -> IO ()
replyError conn e = do
  let rep = case fromException e of
        Just (ioe :: IOException) ->
          if
            | isDoesNotExistError ioe -> HostUnreachable
            | isPermissionError ioe -> ConnectionNotAllowedByRuleset
            | otherwise -> GeneralSOCKSFailure
        _ -> GeneralSOCKSFailure
  putStrLn $ "Replying with error: " ++ show rep
  encodeAndSend conn $ Reply rep (AddressIPv4 "0.0.0.0") 0
  throwIO e
