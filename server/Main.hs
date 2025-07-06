import Network.SOCKS5.Server
import Options.Applicative

data Args = Args
  { argHost :: String,
    argPort :: String,
    argUseTLS :: Bool,
    argCertFile :: FilePath,
    argKeyFile :: FilePath
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

  let serverConfig =
        ServerConfig
          { serverHost = argHost args,
            serverPort = argPort args,
            useTLS = argUseTLS args,
            certFile = argCertFile args,
            keyFile = argKeyFile args
          }

  runSOCKS5Server serverConfig
