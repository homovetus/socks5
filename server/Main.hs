module Main (main) where

import Network.SOCKS5.Server

main :: IO ()
main = runSOCKS5Server "0.0.0.0" "10800"
