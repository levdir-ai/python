import logging
import configparser
from cls.typeclass import ConnectionParam
from time import sleep

def Logo():
	return """
            _____                 
          ,888888b.               
        .d888888888b              
    _..-'.`*'_,88888b             
  ,'..-..`"ad88888888b.           
         ``-. `*Y888888b.         
             \   `Y888888b.       
             :     Y8888888b.     
             :      Y88888888b.   
             |    _,8ad88888888.  
             : .d88888888888888b. 
             \d888888888888888888 
             8888;'''`88888888888 
             888'     Y8888888888 
             `Y8      :8888888888 
              |`      '8888888888 
              |        8888888888 
              |       ,888888888P 
              :       ;888888888' 
               \      d88888888'  
              _.>,    888888P'    
            <,--''`.._>8888(      
             `>__...--' `''`

		Penguin & Co
"""

def Logo2():
	s="""
		Crazy Fish & Co

         ^
       //                        ___   ___
     (*)     "O"                /  _   _  \\
    (*)                           / \\ / \\
   (*)    "O"                    |   |   |    |\\
  //                             |O  |O  |___/  \\     ++
 //                               \\_/ \\_/    \\   | ++
//                              _/      __    \\  \\
/     /|   /\\                  (________/ __   |_/
     / |  |  |                   (___      /   |    |\\
    / /  /   |                     \\     \\|    |___/  |
   |  | |   /                       \\_________      _/   ++++
  /   | |  |                      ++           \\    |
 |   / /   |                              ++   |   /  +++
/   /  |   |                               ++ /__/
~~~ ~~~~   ~~~~~~~~~~~~  ~~~~~~~~~~~~~  ~~~~        ~~+++~~~~ ~
                         
"""
	for q in s.splitlines():
		print(q)
		sleep(0.1)
	return 	


class CustomFormatter(logging.Formatter):

    white = "\x1b[1m"
    grey = "\x1b[38;20m"
    green = "\x1b[32m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "(%(filename)s:%(lineno)d):%(levelname)s: %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: green + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)



def LogConfigure(DEBUGLEVELFILE,DEBUGLEVELSCREEN):
#setup logging
    logger = logging.getLogger("main")
#File logging
    logging.basicConfig(filename='log/asgusrv.log', level=DEBUGLEVELFILE, format='%(asctime)s: %(levelname)s:%(module)s.%(funcName)s: %(message)s',datefmt = '%Y-%m-%d %H:%M:%S')
#Console logging
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(CustomFormatter())
    console_handler.setLevel(DEBUGLEVELSCREEN)
    logger.addHandler(console_handler)
    return logger	

def ConfigRead(CfgFile):
    LogLevel={"NOTSET":0,
	"DEBUG":10,
    	"INFO":20,
    	"WARNING":30,
    	"ERROR":40,
    	"CRITICAL":50
    }


#reding configuration
    config = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
    config.read(CfgFile)
    try:
    	HOST = config.get('Connection','Host')  # The server's hostname or IP address
    	PORT = config.getint('Connection','Port')   # The port used by the server
    	ENC= config.get('Connection','Encryption')	
    	PUBKEY = config.get('Other','PublicKey')
    	PRIVKEY = config.get('Other','PrivateKey')
    	LOGFILE = config.get('Logs','LogFile')
    	LOGLEVELSCREEN=LogLevel[config.get('Logs','LogLevelScreen')]
    	LOGLEVELFILE=LogLevel[config.get('Logs','logLevelFile')]
#database connection params
    	CNN = ConnectionParam(
    		dbname=config.get('DBConnection','DBName'),
    		user=config.get('DBConnection','DBUser'),
    		password=config.get('DBConnection','DBPassword'),
    		host=config.get('DBConnection','DBHost')
    	)
    except Exception as err:
    	print("Configuration error:",err)
    	exit()
    return (HOST,PORT, ENC, PUBKEY, PRIVKEY, LOGFILE,LOGLEVELSCREEN,LOGLEVELFILE,CNN)


