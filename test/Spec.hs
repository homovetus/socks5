{-# LANGUAGE OverloadedStrings #-}

import Control.Concurrent
import Control.Concurrent.Async
import Control.Monad
import Control.Monad.State
import Data.Binary (Binary)
import Data.Bits
import Data.ByteString qualified as B
import Data.ByteString.Char8 qualified as C8
import Network.Run.TCP
import Network.SOCKS5.Client
import Network.SOCKS5.Internal
import Network.SOCKS5.Server
import Network.Socket
import Network.Socket.ByteString
import Test.Hspec

type StateIO a = StateT B.ByteString IO a

withSOCKS5Server :: (ClientConfig -> IO a) -> IO a
withSOCKS5Server action = do
  let serverConfig =
        ServerConfig
          { serverHost = "0.0.0.0",
            serverPort = "10800",
            users = []
          }
  withAsync (runSOCKS5Server serverConfig) $ \_ -> do
    threadDelay 200000
    putStrLn "SOCKS5 server started. Running tests..."
    result <- action $ ClientConfig "127.0.0.1" "10800" [NoAuth] Nothing
    putStrLn "Tests finished. Stopping SOCKS5 server..."
    return result

main :: IO ()
main = hspec $ do
  aroundAll withSOCKS5Server $ do
    describe "Network.SOCKS5.Client" $ do
      it "should run TCP connect successfully to ipinfo.io" $ \proxyConfig -> do
        let destAddr = AddressDomain "ipinfo.io"
            destPort = "80"
        runTCPConnect destAddr destPort proxyConfig $ \sock -> do
          let request = C8.pack "GET / HTTP/1.1\r\nHost: ipinfo.io\r\nConnection: close\r\n\r\n"
          putStrLn "Sending HTTP GET request..."
          sendAll sock request
          response <- recv sock 4096
          putStrLn "Received HTTP Response (first 4096 bytes):"
          putStrLn "--------------------------"
          C8.putStrLn response
          putStrLn "--------------------------"
          response `shouldSatisfy` (B.length |> (> 0))
          response `shouldSatisfy` ("HTTP/1.1 200 OK" `B.isPrefixOf`)

      it "should run BIND command successfully" $ \_proxyConfig -> do
        runTCPClient
          "127.0.0.1"
          "10800"
          ( \sock ->
              evalStateT
                ( do
                    liftIO $ encodeAndSend sock $ Hello [NoAuth]
                    method :: MethodSelection <- recvS sock
                    liftIO $ method `shouldBe` MethodSelection NoAuth
                    liftIO $ encodeAndSend sock $ Request Bind (AddressIPv4 "8.8.8.8") 80
                    reply1 <- recvS sock
                    liftIO $ putStrLn $ "Received first BIND reply: " ++ show reply1
                    st <- get
                    liftIO $ boundPort reply1 `shouldSatisfy` (> 0)
                    liftIO
                      $ withAsync
                        ( do
                            threadDelay 100000
                            let connectHost = show (boundAddress reply1)
                            let connectPort = show (boundPort reply1)
                            putStrLn $ "Third-party connector: attempting to connect to " ++ connectHost ++ ":" ++ connectPort
                            runTCPClient connectHost connectPort $ \remoteSock -> do
                              putStrLn "Third-party connector: connection successful."
                              forever $ sendAll remoteSock "PING"
                        )
                      $ \connectorAsync -> do
                        putStrLn "Main thread: waiting for second BIND reply..."
                        reply2 :: Reply <- evalStateT (recvS sock) st
                        putStrLn $ "Main thread: received second BIND reply: " ++ show reply2
                        ping <- recv sock 4
                        cancel connectorAsync
                        ping `shouldBe` "PING"
                )
                B.empty
          )

      it "should run UDP associate successfully and perform a DNS query" $ \proxyConfig -> do
        runUDPAssociate proxyConfig $ \sendUDP recvUDP -> do
          let dnsServerAddr = SockAddrInet 53 (tupleToHostAddress (8, 8, 8, 8))
          let dnsQuery =
                B.pack [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01]
          putStrLn $ "Sending DNS query for 'google.com' to " ++ show dnsServerAddr ++ " via proxy..."
          sendUDP dnsQuery dnsServerAddr
          (response, from) <- recvUDP
          putStrLn $ "Received " ++ show (B.length response) ++ " bytes from " ++ show from
          response `shouldSatisfy` (B.length |> (> 0))
          B.take 2 response `shouldBe` B.take 2 dnsQuery
          when (B.length response >= 8) $ do
            let flags = B.unpack $ B.take 2 $ B.drop 2 response
                anCountBytes = B.unpack $ B.take 2 $ B.drop 6 response
                answerCount = (fromIntegral (head anCountBytes) `shiftL` 8) + fromIntegral (last anCountBytes) :: Int
            head flags `shouldSatisfy` (>= 0x80)
            answerCount `shouldSatisfy` (> 0)

(|>) :: (a -> b) -> (b -> Bool) -> a -> Bool
f |> p = p . f

recvS :: (Binary b, Connection c) => c -> StateIO b
recvS conn = do
  buffer <- get
  (val, left) <- liftIO $ recvAndDecode conn buffer
  put left
  return val
