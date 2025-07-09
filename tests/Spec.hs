{-# LANGUAGE OverloadedStrings #-}

import Control.Concurrent
import Control.Concurrent.Async
import Control.Monad
import Data.Bits
import Data.ByteString qualified as B
import Data.ByteString.Char8 qualified as C8
import Data.Default
import Network.Run.TCP
import Network.SOCKS5.Client
import Network.SOCKS5.Server
import Network.Socket
import Network.Socket.ByteString
import Network.TLS
import Network.TLS.Extra.Cipher
import Test.Hspec

main :: IO ()
main = hspec $ do
  aroundAll withSOCKS5Server $ do
    describe "Network.SOCKS5.Client" $ do
      it "should run TCP connect successfully to ipinfo.io" $ \proxyConfig -> do
        let destAddr = "ipinfo.io"
            destPort = 80
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

      it "should run BIND command successfully" $ \proxyConfig -> do
        let destAddr = "8.8.8.8"
            destPort = 80
        runTCPBind
          destAddr
          destPort
          proxyConfig
          ( \boundAddr boundPort -> do
              void $ async $ do
                threadDelay 200000
                putStrLn $ "Third-party connector attempting to connect to " ++ show boundAddr ++ ":" ++ show boundPort
                runTCPClient boundAddr (show boundPort) $ \remoteSock -> do
                  putStrLn "Third-party connector: connection successful."
                  forever $ sendAll remoteSock "PING"
          )
          ( \_ _ sock -> do
              putStrLn "SOCKS5 client: received connection, waiting for data..."
              ping <- recv sock 4
              putStrLn "SOCKS5 client: received data."
              ping `shouldBe` "PING"
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

  aroundAll withSOCKS5ServerTLS $ do
    describe "Network.SOCKS5.Client" $ do
      it "should run TCP connect successfully to ipinfo.io with TLS" $ \(proxyConfig, clientParams) -> do
        let destAddr = "ipinfo.io"
            destPort = 80
        runTCPConnectTLS destAddr destPort proxyConfig clientParams $ \ctx -> do
          let request = C8.pack "GET / HTTP/1.1\r\nHost: ipinfo.io\r\nConnection: close\r\n\r\n"
          putStrLn "Sending HTTP GET request..."
          sendData ctx $ C8.fromStrict request
          response <- recvData ctx
          putStrLn "Received HTTP Response:"
          putStrLn "--------------------------"
          C8.putStrLn response
          putStrLn "--------------------------"
          response `shouldSatisfy` (B.length |> (> 0))
          response `shouldSatisfy` ("HTTP/1.1 200 OK" `B.isPrefixOf`)

      it "should run BIND command successfully with TLS" $ \(proxyConfig, clientParams) -> do
        let destAddr = "8.8.8.8"
            destPort = 80
        runTCPBindTLS
          destAddr
          destPort
          proxyConfig
          clientParams
          ( \boundAddr boundPort -> do
              void $ async $ do
                threadDelay 200000
                putStrLn $ "Third-party connector attempting to connect to " ++ show boundAddr ++ ":" ++ show boundPort
                runTCPClient boundAddr (show boundPort) $ \remoteSock -> do
                  putStrLn "Third-party connector: connection successful."
                  sendAll remoteSock "PING"
          )
          ( \_ _ ctx -> do
              putStrLn "SOCKS5 client: received connection, waiting for data..."
              ping <- recvData ctx
              putStrLn "SOCKS5 client: received data."
              ping `shouldBe` "PING"
          )

      it "should run UDP associate successfully and perform a DNS query with TLS" $ \(proxyConfig, clientParams) -> do
        runUDPAssociateTLS proxyConfig clientParams $ \sendUDP recvUDP -> do
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

withSOCKS5Server :: (ClientConfig -> IO a) -> IO a
withSOCKS5Server action = do
  let serverConfig =
        ServerConfig
          { serverHost = "0.0.0.0",
            serverPort = "10800",
            users = [("testuser", "testpass")]
          }
  withAsync (runSOCKS5Server serverConfig) $ \_ -> do
    threadDelay 200000
    putStrLn "SOCKS5 server started. Running tests..."
    result <- action $ ClientConfig "127.0.0.1" "10800" (Just ("testuser", "testpass"))
    putStrLn "Tests finished. Stopping SOCKS5 server..."
    return result

withSOCKS5ServerTLS :: ((ClientConfig, ClientParams) -> IO a) -> IO a
withSOCKS5ServerTLS action = do
  let serverConfig =
        ServerConfig
          { serverHost = "0.0.0.0",
            serverPort = "10800",
            users = [("testuser", "testpass")]
          }
  serverParams <- credential "tests/cert.pem" "tests/key.pem"
  withAsync (runSOCKS5ServerTLS serverConfig serverParams) $ \_ -> do
    threadDelay 200000
    putStrLn "SOCKS5 TLS server started. Running tests..."
    let clientConfig = ClientConfig "127.0.0.1" "10800" (Just ("testuser", "testpass"))
    let clientParams =
          (defaultParamsClient "127.0.0.1" "")
            { clientSupported =
                def
                  { supportedCiphers = ciphersuite_strong
                  },
              clientShared =
                def
                  { sharedValidationCache = ValidationCache (\_ _ _ -> return ValidationCachePass) (\_ _ _ -> return ())
                  }
            }
    result <- action (clientConfig, clientParams)
    putStrLn "Tests finished. Stopping SOCKS5 TLS server..."
    return result

credential :: FilePath -> FilePath -> IO ServerParams
credential cert key = do
  cred <- either error id <$> credentialLoadX509 cert key
  return
    (defaultParamsServer :: ServerParams)
      { serverShared =
          def
            { sharedCredentials = Credentials [cred]
            },
        serverSupported =
          def
            { supportedCiphers = ciphersuite_strong
            }
      }

(|>) :: (a -> b) -> (b -> Bool) -> a -> Bool
f |> p = p . f
