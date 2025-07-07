import Data.Default
import Data.Text.Lazy qualified as LT
import Network.SOCKS5.Server
import Network.TLS
import Network.TLS.Extra.Cipher
import Options.Applicative

data Args = Args
  { host :: String,
    port :: String,
    useTLS :: Bool,
    cert :: FilePath,
    key :: FilePath,
    userPass :: [String]
  }

argsParser :: Parser Args
argsParser =
  Args
    <$> strOption
      ( long "host"
          <> short 'H'
          <> metavar "HOSTNAME"
          <> value "0.0.0.0"
          <> showDefault
          <> help "The hostname to bind the server to."
      )
    <*> strOption
      ( long "port"
          <> short 'P'
          <> metavar "PORT"
          <> value "1080"
          <> showDefault
          <> help "The port to listen on."
      )
    <*> switch
      ( long "tls"
          <> help "Enable TLS encryption. Requires --cert and --key."
      )
    <*> strOption
      ( long "cert"
          <> metavar "CERT_FILE"
          <> value "cert.pem"
          <> showDefault
          <> help "The TLS certificate file."
      )
    <*> strOption
      ( long "key"
          <> metavar "KEY_FILE"
          <> value "key.pem"
          <> showDefault
          <> help "The TLS private key file."
      )
    <*> many
      ( strOption
          ( long "user-pass"
              <> short 'u'
              <> metavar "USERNAME:PASSWORD"
              <> help "User/password pair for authentication. Can be specified multiple times."
          )
      )

parseUserPass :: String -> (LT.Text, LT.Text)
parseUserPass s = case break (== ':') s of
  (user, ':' : pass) | not (null user) && not (null pass) -> (LT.pack user, LT.pack pass)
  _ -> error $ "Invalid format for user-pass. Expected USERNAME:PASSWORD, but got: " ++ s

main :: IO ()
main = do
  args <-
    execParser $
      info
        (argsParser <**> helper)
        ( fullDesc
            <> progDesc "Run a SOCKS5 proxy server."
            <> header "socks5-server - A simple SOCKS5 proxy"
        )

  let users = map parseUserPass (userPass args)
  let serverConfig =
        ServerConfig
          { serverHost = host args,
            serverPort = port args,
            users = users
          }
  if useTLS args
    then do
      params <- credential (cert args) (key args)
      runSOCKS5ServerTLS serverConfig params
    else runSOCKS5Server serverConfig

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
