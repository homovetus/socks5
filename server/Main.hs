import Data.Text.Lazy qualified as LT
import Network.SOCKS5.Server
import Options.Applicative

data Args = Args
  { argHost :: String,
    argPort :: String,
    argUseTLS :: Bool,
    argCertFile :: FilePath,
    argKeyFile :: FilePath,
    argUsername :: Maybe String,
    argPassword :: Maybe String
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
          <> short 'p'
          <> metavar "PORT"
          <> value "10800"
          <> showDefault
          <> help "The port to listen on."
      )
    <*> switch
      ( long "tls"
          <> help "Enable TLS encryption. Requires --cert-file and --key-file."
      )
    <*> strOption
      ( long "cert-file"
          <> metavar "CERT_FILE"
          <> value "cert.pem"
          <> showDefault
          <> help "The TLS certificate file."
      )
    <*> strOption
      ( long "key-file"
          <> metavar "KEY_FILE"
          <> value "key.pem"
          <> showDefault
          <> help "The TLS private key file."
      )
    <*> optional
      ( strOption
          ( long "username"
              <> short 'u'
              <> metavar "USERNAME"
              <> help "The username for authentication."
          )
      )
    <*> optional
      ( strOption
          ( long "password"
              <> short 'P'
              <> metavar "PASSWORD"
              <> help "The password for authentication."
          )
      )

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
  let users = case (argUsername args, argPassword args) of
        (Just user, Just pass) -> [(LT.pack user, LT.pack pass)]
        _ -> []
  let serverConfig =
        ServerConfig
          { serverHost = argHost args,
            serverPort = argPort args,
            useTLS = argUseTLS args,
            certFile = argCertFile args,
            keyFile = argKeyFile args,
            users = users
          }

  runSOCKS5Server serverConfig
