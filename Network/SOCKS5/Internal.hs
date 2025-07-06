module Network.SOCKS5.Internal
  ( Method (..),
    Command (..),
    Address (..),
    fromSockAddr_,
    toSockAddr_,
    Hello (..),
    MethodSelection (..),
    Request (..),
    Rep (..),
    Reply (..),
    UDPRequest (..),
    sendUDPRequestTo,
    SOCKSException (..),
    Connection (..),
    recvAndDecode,
    encodeAndSend,
  )
where

import Control.Exception
import Control.Monad
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Data.ByteString qualified as B
import Data.ByteString.Lazy qualified as LB
import Data.IP
import Data.Text.Lazy qualified as LT
import Data.Text.Lazy.Encoding qualified as LTE
import Network.Socket
import Network.Socket.ByteString qualified as SB
import Network.Socket.ByteString.Lazy qualified as LSB
import Network.TLS
import Prelude hiding (getContents)

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

data Command
  = Connect
  | Bind
  | UDPAssociate
  deriving (Eq, Show)

instance Binary Command where
  put :: Command -> Put
  put Connect = putWord8 0x01
  put Bind = putWord8 0x02
  put UDPAssociate = putWord8 0x03

  get :: Get Command
  get = do
    cmd <- getWord8
    case cmd of
      0x01 -> return Connect
      0x02 -> return Bind
      0x03 -> return UDPAssociate
      _ -> fail $ "Unknown command: " ++ show cmd

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

--  The client connects to the server, and sends a version
--  identifier/method selection message:
--    +-----+----------+----------+
--    | VER | NMETHODS | METHODS  |
--    +-----+----------+----------+
--    |  1  |    1     | 1 to 255 |
--    +-----+----------+----------+

newtype Hello = Hello
  { methods :: [Method]
  }
  deriving (Eq, Show)

instance Binary Hello where
  put :: Hello -> Put
  put (Hello methods) = do
    putWord8 5
    putWord8 (fromIntegral $ length methods)
    mapM_ put methods

  get :: Get Hello
  get = do
    void getWord8
    nMethods <- getWord8
    methods <- replicateM (fromIntegral nMethods) get
    return $ Hello methods

--  The server selects from one of the methods given in METHODS, and
--  sends a METHOD selection message:
--    +-----+--------+
--    | VER | METHOD |
--    +-----+--------+
--    |  1  |   1    |
--    +-----+--------+

newtype MethodSelection = MethodSelection
  { method :: Method
  }
  deriving (Eq, Show)

instance Binary MethodSelection where
  put :: MethodSelection -> Put
  put (MethodSelection method) = do
    putWord8 5
    put method

  get :: Get MethodSelection
  get = do
    void getWord8
    MethodSelection <$> get

--  The SOCKS request is formed as follows:
--    +-----+-----+-------+------+----------+----------+
--    | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
--    +-----+-----+-------+------+----------+----------+
--    |  1  |  1  | X'00' |  1   | Variable |    2     |
--    +-----+-----+-------+------+----------+----------+
--  Where:
--    VER: protocol version: X'05'
--    CMD:
--      CONNECT:       X'01'
--      BIND:          X'02'
--      UDP ASSOCIATE: X'03'
--    RSV: RESERVED
--    ATYP: address type of following address:
--      IP V4 address: X'01'
--      DOMAINNAME:    X'03'
--      IP V6 address: X'04'
--    DST.ADDR: desired destination address
--    DST.PORT: desired destination port in network octet order

data Request = Request
  { command :: Command,
    destinationAddress :: Address,
    destinationPort :: PortNumber
  }
  deriving (Eq, Show)

instance Binary Request where
  put :: Request -> Put
  put (Request command destinationAddress destinationPort) = do
    putWord8 0x05
    put command
    putWord8 0x00 -- RSV
    put destinationAddress
    putWord16be $ fromIntegral destinationPort

  get :: Get Request
  get = do
    void getWord8
    command <- get
    void getWord8 -- RSV, ignored
    address <- get
    port <- getWord16be
    let destinationPort = fromIntegral port
    return $ Request command address destinationPort

--  The server evaluates the request, and
--  returns a reply formed as follows:
--    +-----+-----+-------+------+----------+----------+
--    | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
--    +-----+-----+-------+------+----------+----------+
--    |  1  |  1  | X'00' |  1   | Variable |    2     |
--    +-----+-----+-------+------+----------+----------+
--  Where:
--  VER: protocol version: X'05'
--  REP: Reply field:
--    X'00': succeeded
--    X'01': general SOCKS server failure
--    X'02': connection not allowed by ruleset
--    X'03': Network unreachable
--    X'04': Host unreachable
--    X'05': Connection refused
--    X'06': TTL expired
--    X'07': Command not supported
--    X'08': Address type not supported
--    X'09': to X'FF' unassigned
--  RSV: RESERVED
--  ATYP: address type of following address
--    IP V4 address: X'01'
--    DOMAINNAME: X'03'
--    IP V6 address: X'04'
--  BND.ADDR: server bound address
--  BND.PORT: server bound port in network octet order

data Rep
  = Succeeded
  | GeneralSOCKSFailure
  | ConnectionNotAllowedByRuleset
  | NetworkUnreachable
  | HostUnreachable
  | ConnectionRefused
  | TTLExpired
  | CommandNotSupported
  | AddressTypeNotSupported
  | Unassigned Word8
  deriving (Eq, Show)

instance Binary Rep where
  put :: Rep -> Put
  put Succeeded = putWord8 0x00
  put GeneralSOCKSFailure = putWord8 0x01
  put ConnectionNotAllowedByRuleset = putWord8 0x02
  put NetworkUnreachable = putWord8 0x03
  put HostUnreachable = putWord8 0x04
  put ConnectionRefused = putWord8 0x05
  put TTLExpired = putWord8 0x06
  put CommandNotSupported = putWord8 0x07
  put AddressTypeNotSupported = putWord8 0x08
  put (Unassigned m) = putWord8 m

  get :: Get Rep
  get = do
    rep <- getWord8
    case rep of
      0x00 -> return Succeeded
      0x01 -> return GeneralSOCKSFailure
      0x02 -> return ConnectionNotAllowedByRuleset
      0x03 -> return NetworkUnreachable
      0x04 -> return HostUnreachable
      0x05 -> return ConnectionRefused
      0x06 -> return TTLExpired
      0x07 -> return CommandNotSupported
      0x08 -> return AddressTypeNotSupported
      _ -> return $ Unassigned rep

data Reply = Reply
  { reply :: Rep,
    boundAddress :: Address,
    boundPort :: PortNumber
  }
  deriving (Eq, Show)

instance Binary Reply where
  put :: Reply -> Put
  put (Reply reply bindAddress boundPort) = do
    putWord8 0x05
    put reply
    putWord8 0x00 -- RSV
    put bindAddress
    putWord16be $ fromIntegral boundPort

  get :: Get Reply
  get = do
    void getWord8
    reply <- get
    void getWord8 -- RSV, ignored
    address <- get
    port <- getWord16be
    let boundPort = fromIntegral port
    return $ Reply reply address boundPort

--  Each UDP datagram carries a UDP request header with it:
--    +-----+------+------+----------+----------+----------+
--    | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
--    +-----+------+------+----------+----------+----------+
--    |  2  |  1   |  1   | Variable |    2     | Variable |
--    +-----+------+------+----------+----------+----------+
--  The fields in the UDP request header are:
--    RSV: Reserved X'0000'
--    FRAG: Current fragment number
--    ATYP: address type of following addresses:
--      IP V4 address: X'01'
--      DOMAINNAME:    X'03'
--      IP V6 address: X'04'
--    DST.ADDR: desired destination address
--    DST.PORT: desired destination port
--    DATA: user data

data UDPRequest = UDPRequest
  { frag :: Word8,
    address :: Address,
    port :: PortNumber,
    payload :: LB.ByteString
  }
  deriving (Eq, Show)

instance Binary UDPRequest where
  put :: UDPRequest -> Put
  put (UDPRequest frag addr port p) = do
    putWord16be 0x0000 -- RSV
    putWord8 frag
    put addr
    putWord16be $ fromIntegral port
    putLazyByteString p

  get :: Get UDPRequest
  get = do
    void getWord16be -- RSV
    frag <- getWord8
    addr <- get
    port <- getWord16be
    let portNum = fromIntegral port
    UDPRequest frag addr portNum <$> getRemainingLazyByteString

sendUDPRequestTo :: Socket -> Word8 -> Address -> PortNumber -> LB.ByteString -> SockAddr -> IO ()
sendUDPRequestTo sock frag addr port payload =
  SB.sendAllTo sock $ LB.toStrict $ encode $ UDPRequest frag addr port payload

data SOCKSException
  = HandshakeFail Reply
  | AuthUnsupported Method
  | PortStringInvalid ServiceName
  | NoAcceptableAuthMethods
  | ConnectionToTargetFailed SomeException
  deriving (Show)

instance Exception SOCKSException

class Connection c where
  connRecv :: c -> IO B.ByteString
  connSend :: c -> LB.ByteString -> IO ()

instance Connection Socket where
  connRecv :: Socket -> IO B.ByteString
  connRecv sock = SB.recv sock 4096

  connSend :: Socket -> LB.ByteString -> IO ()
  connSend = LSB.sendAll

instance Connection Context where
  connRecv :: Context -> IO B.ByteString
  connRecv = recvData

  connSend :: Context -> LB.ByteString -> IO ()
  connSend = sendData

recvAndDecode :: (Binary a, Connection c) => c -> B.ByteString -> IO (a, B.ByteString)
recvAndDecode conn buffer = go $ pushChunk (runGetIncremental get) buffer
  where
    go :: Decoder a -> IO (a, B.ByteString)
    go (Done left _ val) = return (val, left)
    go (Fail _ _ err) = throwIO $ userError $ "SOCKS5 parse error: " ++ err
    go (Partial k) = do
      chunk <- connRecv conn
      if B.null chunk
        then go (k Nothing)
        else go (k (Just chunk))

encodeAndSend :: (Binary a, Connection c) => c -> a -> IO ()
encodeAndSend conn val = do
  connSend conn $ encode val
