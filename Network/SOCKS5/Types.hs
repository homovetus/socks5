-- Types you may want to import.
module Network.SOCKS5.Types
  ( Method (..),
    Address (..),
    fromSockAddr_,
    toSockAddr_,
  )
where

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString.Lazy qualified as LB
import Data.IP
import Data.Text.Lazy qualified as LT
import Data.Text.Lazy.Encoding qualified as LTE
import Network.Socket

--  The values currently defined for METHOD are:
--    X'00': NO AUTHENTICATION REQUIRED
--    X'01': GSSAPI
--    X'02': USERNAME/PASSWORD
--    X'03': to X'7F' IANA ASSIGNED
--    X'80': to X'FE' RESERVED FOR PRIVATE METHODS
--    X'FF': NO ACCEPTABLE METHODS

data Method
  = NoAuth
  | GSSAPI
  | UserPass
  | IANAAssigned Word8
  | PrivateMethod Word8
  | NoAcceptableMethods
  | UnknownMethod Word8
  deriving (Eq, Show)

instance Binary Method where
  put :: Method -> Put
  put NoAuth = putWord8 0x00
  put GSSAPI = putWord8 0x01
  put UserPass = putWord8 0x02
  put (IANAAssigned m) = putWord8 m
  put (PrivateMethod m) = putWord8 m
  put NoAcceptableMethods = putWord8 0xFF
  put (UnknownMethod m) = putWord8 m

  get :: Get Method
  get = do
    m <- getWord8
    case m of
      0x00 -> return NoAuth
      0x01 -> return GSSAPI
      0x02 -> return UserPass
      _ | m >= 0x03 && m <= 0x7F -> return $ IANAAssigned m
      _ | m >= 0x80 && m <= 0xFE -> return $ PrivateMethod m
      0xFF -> return NoAcceptableMethods
      _ -> return $ UnknownMethod m

-- | Address type used for destination addresses in SOCKS5 protocol.
data Address
  = AddressIPv4 IPv4
  | AddressIPv6 IPv6
  | AddressDomain LT.Text
  deriving (Eq)

instance Show Address where
  show :: Address -> String
  show (AddressIPv4 ip) = show ip
  show (AddressIPv6 ip) = show ip
  show (AddressDomain name) = LT.unpack name

instance Binary Address where
  put :: Address -> Put
  put (AddressIPv4 ip) = do
    putWord8 0x01
    putWord32be $ fromIPv4w ip
  put (AddressIPv6 ip) = do
    putWord8 0x04
    let (a1, a2, a3, a4) = fromIPv6w ip
     in mapM_ putWord32be [a1, a2, a3, a4]
  put (AddressDomain name) = do
    putWord8 0x03
    let encodedName = LTE.encodeUtf8 name
        byteLength = LB.length encodedName
    if byteLength > fromIntegral (maxBound :: Word8)
      then
        error $
          "DomainName (UTF-8 encoded) has length of "
            ++ show byteLength
            ++ " bytes. Max allowed is "
            ++ show (maxBound :: Word8)
      else putWord8 $ fromIntegral byteLength
    putLazyByteString encodedName

  get :: Get Address
  get = do
    addrType <- getWord8
    case addrType of
      0x01 -> do
        AddressIPv4 . toIPv4w <$> getWord32be
      0x04 -> do
        a1 <- getWord32be
        a2 <- getWord32be
        a3 <- getWord32be
        a4 <- getWord32be
        return $ AddressIPv6 $ toIPv6w (a1, a2, a3, a4)
      0x03 -> do
        len <- getWord8
        encodedName <- getLazyByteString (fromIntegral len)
        case LTE.decodeUtf8' encodedName of
          Left err -> fail $ "Failed to decode UTF-8 domain name: " ++ show err
          Right name -> return $ AddressDomain name
      _ -> fail $ "Unknown address type: " ++ show addrType

fromSockAddr_ :: SockAddr -> (Address, PortNumber)
fromSockAddr_ (SockAddrInet port host) = (AddressIPv4 (fromHostAddress host), fromIntegral port)
fromSockAddr_ (SockAddrInet6 port _ host _) = (AddressIPv6 (toIPv6w host), fromIntegral port)
fromSockAddr_ path = error $ "Unexpected Unix socket address: " ++ show path

toSockAddr_ :: Address -> PortNumber -> SockAddr
toSockAddr_ (AddressIPv4 host) port = SockAddrInet (fromIntegral port) $ toHostAddress host
toSockAddr_ (AddressIPv6 host) port = SockAddrInet6 (fromIntegral port) 0 (toHostAddress6 host) 0
toSockAddr_ (AddressDomain host) _ = error $ "Address conversion for DomainName not implemented: " ++ show host
