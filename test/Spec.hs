{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- For C8.pack and C8.putStrLn
-- Hide recv from Network.Socket to avoid clash with SOCKS5.Client.recv
-- Explicitly import sendAll and recv from Network.Socket.ByteString

import Control.Concurrent (threadDelay)
import Control.Concurrent.Async (withAsync)
import Control.Exception
import Control.Monad
import Data.Bits
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as C8
import Network.Run.TCP
import Network.SOCKS5.Client
import Network.SOCKS5.Internal
import Network.SOCKS5.Server
import Network.Socket
import Network.Socket.ByteString
import Test.Hspec

-- | Manages the SOCKS5 server lifecycle for the test suite.
-- It starts the server, runs the tests, and guarantees cleanup.
withSOCKS5Server :: (ClientConfig -> IO a) -> IO a
withSOCKS5Server action = do
  let host = "127.0.0.1"
      port = "10800"
      server = runSOCKS5Server "0.0.0.0" port
      proxyConfig = ClientConfig host port NoAuth

  -- withAsync ensures the server is started in a background thread
  -- and is automatically stopped when the inner action finishes or throws an exception.
  putStrLn "Starting SOCKS5 proxy for tests..."
  withAsync server $ \_ -> do
    -- Give the server a moment to start up to avoid race conditions.
    -- 200ms should be plenty for a local server.
    threadDelay 200000
    putStrLn "SOCKS5 proxy started. Running tests..."
    -- Run the actual tests, passing them the config they need.
    result <- action proxyConfig
    putStrLn "Tests finished. Stopping SOCKS5 proxy..."
    return result

main :: IO ()
main = hspec $ do
  -- `aroundAll` applies our server-management function to the entire `describe` block.
  -- The `proxyConfig` is created by `withSOCKS5Server` and passed to our tests.
  aroundAll withSOCKS5Server $ do
    describe "Network.SOCKS5.Client" $ do
      -- IMPORTANT: The tests now accept `proxyConfig` as a parameter.

      it "should run TCP connect successfully to ipinfo.io" $ \proxyConfig -> do
        let targetHost = AddressDomain "ipinfo.io"
            targetPort = "80"

        result <- try @SomeException $ runTCPConnect proxyConfig targetHost targetPort $ \sock -> do
          putStrLn $ "Connected to " ++ show targetHost ++ " through SOCKS5 proxy"
          let request = C8.pack "GET / HTTP/1.1\r\nHost: ipinfo.io\r\nConnection: close\r\n\r\n"
          putStrLn "Sending HTTP GET request..."
          sendAll sock request
          response <- recv sock 4096
          putStrLn "Received HTTP Response (first 4096 bytes):"
          putStrLn "--------------------------"
          C8.putStrLn response
          putStrLn "--------------------------"

          response `shouldSatisfy` (BS.length .> (> 0))
          response `shouldSatisfy` ("HTTP/1.1 200 OK" `BS.isPrefixOf`)
          response `shouldSatisfy` ("{\n  \"ip\":" `BS.isInfixOf`)

        case result of
          Left e -> expectationFailure $ "TCP connect test failed with exception: " ++ show e
          Right () -> pure () -- Test passed

      -- NOTE: The FTP test requires a real FTP server running on localhost:21.
      -- This test is often disabled unless a specific test environment is set up.
      xit "should run TCP bind successfully with FTP" $ \proxyConfig -> do
        let targetHost = AddressDomain "ftp://ftp.cs.brown.edu"
            targetPort = "21"

        result <-
          try @SomeException $
            runTCPBind
              proxyConfig
              targetHost
              targetPort
              ( \listenAddr listenPort -> do
                  putStrLn $ "Listening on " ++ show listenAddr ++ ":" ++ show listenPort
                  runTCPClient "127.0.0.1" "21" $ \ftpCmdSock -> do
                    let portCmd = "PORT " ++ show listenAddr ++ "," ++ show (listenPort `div` 256) ++ "," ++ show (listenPort `mod` 256) ++ "\n"
                    sendAll ftpCmdSock (C8.pack portCmd)
                    return ()
              )
              ( \peerAddr peerPort sock -> do
                  putStrLn $ "Accepted connection from " ++ show peerAddr ++ ":" ++ show peerPort
                  let testData = "Hello from FTP server"
                  sendAll sock (C8.pack testData)
                  receivedData <- recv sock 1024
                  receivedData `shouldBe` C8.pack testData
              )

        case result of
          Left e -> expectationFailure $ "TCP bind test failed with exception: " ++ show e
          Right () -> pure ()

      it "should run UDP associate successfully and perform a DNS query" $ \proxyConfig -> do
        result <- try @SomeException $ runUDPAssociate proxyConfig $ \sendUDP recvUDP -> do
          let dnsServerAddr = SockAddrInet 53 (tupleToHostAddress (8, 8, 8, 8))
          let dnsQuery =
                BS.pack [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01]

          putStrLn $ "Sending DNS query for 'google.com' to " ++ show dnsServerAddr ++ " via proxy..."
          sendUDP dnsQuery dnsServerAddr

          putStrLn "Waiting for DNS response from proxy..."
          (response, from) <- recvUDP
          putStrLn $ "Received " ++ show (BS.length response) ++ " bytes from " ++ show from

          response `shouldSatisfy` (BS.length .> (> 0))
          BS.take 2 response `shouldBe` BS.take 2 dnsQuery
          when (BS.length response >= 8) $ do
            let flags = BS.unpack $ BS.take 2 $ BS.drop 2 response
                anCountBytes = BS.unpack $ BS.take 2 $ BS.drop 6 response
                answerCount = (fromIntegral (head anCountBytes) `shiftL` 8) + fromIntegral (last anCountBytes) :: Int
            head flags `shouldSatisfy` (>= 0x80)
            answerCount `shouldSatisfy` (> 0)

        case result of
          Left e -> expectationFailure $ "UDP associate test failed with exception: " ++ show e
          Right () -> pure () -- Test passed

-- Helper for `shouldSatisfy` with a function
(.>) :: (a -> b) -> (b -> Bool) -> a -> Bool
f .> p = p . f
