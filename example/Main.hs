{-# LANGUAGE OverloadedStrings #-}

import qualified Data.ByteString.Char8 as C8
import Network.SOCKS5.Client
import Network.SOCKS5.Types
import Network.Socket.ByteString (recv, sendAll)

main :: IO ()
main = do
  let proxyConfig =
        ClientConfig
          { proxyHost = "127.0.0.1",
            proxyPort = "11451",
            auth = [NoAuth],
            userPass = Nothing
          }
  let destAddr = AddressDomain "example.com"
  let destPort = "80"

  runTCPConnect destAddr destPort proxyConfig $ \sock -> do
    putStrLn "Connected to example.com through SOCKS5 proxy!"
    sendAll sock "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    response <- recv sock 4096
    C8.putStrLn response
