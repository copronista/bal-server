
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tokio::net::TcpListener;
use hyper_util::rt::TokioIo;


use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;


use std::time::{SystemTime,UNIX_EPOCH};
use std::sync::Arc;
use std::collections::HashMap;
use sqlite::{State,Connection};

use bitcoin::{consensus, Transaction, Network};

use hex_conservative::FromHex;
use regex::Regex;
use serde::{Serialize, Deserialize};
use log::{info,error,trace,debug};
use serde_json;

#[derive(Debug, Serialize, Deserialize)]
struct NetConfig {
    address: String,
    fixed_fee: u64,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            address: "".to_string(),
            fixed_fee: 10000,
        }
    }
}

impl NetConfig {
    fn default_regtest() -> Self {
        NetConfig {
            address: "bcrt1qzx38ch5gpa0dla2v2sycxpzx4zsrfre3s5et5h".to_string(),
            fixed_fee: 10000,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MyConfig {
    regtest: NetConfig,
    signet: NetConfig,
    testnet4: NetConfig,
    testnet3: NetConfig,
    mainnet: NetConfig,
    bind_address: String,
    bind_port: u16, // Changed to u16 for port numbers
    requests_file: String,
    db_file: String,
}

impl Default for MyConfig {
    fn default() -> Self {
        MyConfig {
            regtest: NetConfig::default_regtest(),
            signet: NetConfig::default(), // Use default for other networks
            testnet4: NetConfig::default(),
            testnet3: NetConfig::default(),
            mainnet: NetConfig::default(),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 9137, // Ensure this is a u16
            requests_file: "rawrequests.log".to_string(),
            db_file: "../bal.db".to_string(),
        }
    }
}
impl MyConfig {
    fn get_net_config(&self, param: &str) -> &NetConfig{
        match param {
            "regtest" => &self.regtest,
            "testnet" => &self.testnet3,
            "signet" => &self.signet,
            _ => &self.mainnet, 
        }
    }
}

/*
async fn collect_body(req: Request<hyper::body::Frame<Bytes>>, len:i32) -> Result<Bytes, hyper::Error> {
    info!("collect body:{}",len);
    let mut body_bytes = Vec::new();
    let mut stream = req.into_body();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(data) => {
                body_bytes.extend_from_slice(&data);
                if body_bytes.len() >= len {
                    body_bytes.truncate(len);
                    break;
                }
            }
            Err(_) => {
                break;
            }
        }
    }

    Ok(body_bytes)
}
*/
async fn echo_info(
                   param: &str,
                   cfg: &MyConfig,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        info!("echo info!!!{}",param);
        let netconfig=MyConfig::get_net_config(cfg,param);
        return Ok(Response::new(full("{\"address\":\"".to_owned()+&netconfig.address+"\",\"base_fee\":\""+&netconfig.fixed_fee.to_string()+"\"}")));
}
async fn echo_search(whole_body: &Bytes,
                     cfg: &MyConfig,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    info!("echo search!!!");
    let strbody = std::str::from_utf8(&whole_body).unwrap();
    info!("{}",strbody);
    trace!("{}",strbody.len());

    let mut response = Response::new(full("Bad data received".to_owned()));
    *response.status_mut() = StatusCode::BAD_REQUEST; // Set status to 400
                                                      //
                                                      //
    if strbody.len() >0 && strbody.len()<=70 {
        let db = sqlite::open(&cfg.db_file).unwrap();
        trace!("qua ci arrivo");
        let mut statement = db.prepare("SELECT * FROM tbl_tx WHERE txid = ?").unwrap();
        statement.bind((1, strbody)).unwrap();

        while let Ok(State::Row) = statement.next() {
            trace!("qua tutto ok");
            let mut response_data = HashMap::new();
            match statement.read::<String, _>("status") {
                Ok(value) => response_data.insert("status", value),
                Err(e) => {
                    error!("Error reading status: {}", e);
                    break;
                    //response_data.insert("status", "Error".to_string())
                }
            };

            // Read the transaction (tx)
            match statement.read::<String, _>("tx") {
                Ok(value) => response_data.insert("tx", value),
                Err(e) => {
                    error!("Error reading tx: {}", e);
                    break;
                    //response_data.insert("tx", "Error".to_string())
                }
            };

            match statement.read::<String, _>("our_address") {
                Ok(value) => response_data.insert("our_address", value),
                Err(e) => {
                    error!("Error reading address: {}", e);
                    break;
                    //response_data.insert("tx", "Error".to_string())
                }
            };

            match statement.read::<String, _>("our_fees") {
                Ok(value) => response_data.insert("our_fees", value),
                Err(e) => {
                    error!("Error reading fees: {}", e);
                    break;
                    //response_data.insert("tx", "Error".to_string())
                }
            };

            // Read the request id (reqid)
            match statement.read::<String, _>("reqid") {
                Ok(value) => response_data.insert("time", value),
                Err(e) => {
                    error!("Error reading reqid: {}", e);
                    break;
                    //response_data.insert("time", "Error".to_string())
                }
            };
            response = match serde_json::to_string(&response_data){
                Ok(json_data) => Response::new(full(json_data)),
                Err(_) => {break;}
            };

            return Ok(response);
        }
    }
    Ok(response)

    
}
async fn echo_push(whole_body: &Bytes,
                   cfg: &MyConfig,
                   param: &str,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        //let whole_body = req.collect().await?.to_bytes();
        let strbody = std::str::from_utf8(&whole_body).unwrap();
        let lines = strbody.split("\n");
        let file = cfg.requests_file.to_string();

        let mut response = Response::new(full("Bad data received".to_owned()));
        *response.status_mut() = StatusCode::BAD_REQUEST; // Set status to 400
        //if !Path::new(&file).exists() {
        //    File::create(&file).unwrap();
        //}
        debug!("network: {}", param);
        let network = match param{
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            &_ => Network::Bitcoin,
        };
        
        let req_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_nanos();
        
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(file)
            .unwrap();
    
        
        let sqltxshead = "INSERT INTO tbl_tx (txid, wtxid, ntxid, tx, locktime, reqid, network, our_address, our_fees)".to_string();
        let mut sqltxs = "".to_string();
        //let mut sqlinps = "INSERT INTO tbl_input (txid, in_txid,in_vout)".to_string();
        //let mut sqlouts = "INSERT INTO tbl_output (txid, script_pubkey, address, amount)\n".to_string();
        let mut union_tx = true;
        let mut already_present = false;
        //let mut union_inps = true;
        //let mut union_outs = true;
        let db = sqlite::open(&cfg.db_file).unwrap();
        let netconfig = MyConfig::get_net_config(cfg,param);
        for line in lines {
            let linea = format!("{req_time}:{line}");
            info!("New Tx: {}", linea);
            if let Err(e) = writeln!(file, "{}",linea) {
                error!("Couldn't write to file: {}", e);
            }
            let raw_tx =  match Vec::<u8>::from_hex(line) {
                Ok(raw_tx) => raw_tx,
                Err(err) => {
                    error!("rawtx error: {}",err);
                    continue
                }
            };
            if raw_tx.len() > 0 {
                trace!("len: {}",raw_tx.len());
                let tx: Transaction = match consensus::deserialize(&raw_tx){
                    Ok(tx) => tx,
                    Err(err) => {error!("error: unable to parse tx: {}\n{}",line,err);continue}
                };
                let txid = tx.txid().to_string();
                trace!("txid: {}",txid);
                let mut statement = db.prepare("SELECT * FROM tbl_tx WHERE txid = ?").unwrap();
                statement.bind((1,&txid[..])).unwrap();
                //statement.bind((1,"Bob")).unwrap();
                if let Ok(State::Row) = statement.next() {
                    already_present=true;
                    continue;
                }
                let ntxid = tx.ntxid();
                let wtxid = tx.wtxid();
                let mut found = false;
                let locktime = tx.lock_time;
                let mut our_fees = 0;
                let mut our_address:String = "".to_string();
                for output in tx.output{
                    let script_pubkey = output.script_pubkey;
                    let address = match bitcoin::Address::from_script(script_pubkey.as_script(), network){
                        Ok(address) => address.to_string(),
                        Err(_) => String::new(),
                    };
                    let amount = output.value;
                    dbg!(&amount); 
                    //search wllexecutor output
                    if address == netconfig.address.to_string() && amount.to_sat() >= netconfig.fixed_fee{
                        our_fees = amount.to_sat();
                        our_address = netconfig.address.to_string();
                        found = true;
                        trace!("address and fees are correct {}: {}",our_address,our_fees);
                        break;
                    }else {
                        trace!("address and fees not found {}: {}",address,amount.to_sat());
                        trace!("address and fees not found {}: {}",netconfig.address.to_string(),netconfig.fixed_fee);
                    }
                }
                if found == false{
                    error!("willexecutor output not found ");
                    //return Ok(response)
                } else {
                    if union_tx == false {
                        sqltxs = format!("{sqltxs} UNION ALL");
                    }else{
                        union_tx = false;
                    }
                    sqltxs = format!("{sqltxs}  SELECT '{txid}', '{wtxid}', '{ntxid}', '{line}', '{locktime}', '{req_time}', '{network}','{our_address}',{our_fees}");
                }

            }            
            else{
                trace!("rawTx len is: {}",raw_tx.len());
            }
            //for input in tx.input{
            //    if !union_inps{
            //        sqlinps = format!("{sqlinps} UNION ALL");
            //    }else{
            //        union_inps = false;
            //    }
            //   let in_txid = input.previous_output.txid;
            //   let in_vout = input.previous_output.vout;
            //   dbg!(input.sequence.is_rbf());

            //   sqlinps = format!("{sqlinps} SELECT \"{txid}\", \"{in_txid}\",\"{in_vout}\"");
            //}
            //for output in tx.output{
            //    if !union_outs {
            //        sqlouts = format!("{sqlouts} UNION ALL");
            //    }else{
            //        union_outs=false;
            //    }
            //    let script_pubkey = output.script_pubkey;
            //    let address = match bitcoin::Address::from_script(script_pubkey.as_script(), network){
            //        Ok(address) => address.to_string(),
            //        Err(_) => String::new(),
            //    };
            //    let amount = output.value;
            //    sqlouts = format!("{sqlouts} SELECT \"{txid}\", \"{script_pubkey}\", \"{address}\", \"{amount}\"\n");

            //}


        }
        debug!("SQL: {}",sqltxs);
        let _ = db.execute("BEGIN TRANSACTION");
        let sql = format!("{}{}",sqltxshead,sqltxs);
        if let Err(err) = db.execute(&sql){
            error!("error executing sql:{} - {}",&sql,err);
            let _ = db.execute("ROLLBACK");
            if already_present == true{
                return Ok(Response::new(full("already present")))
            }
            return Ok(response)
        }
        //if !error {
        //    if let Err(_) = db.execute(sqlinps){
        //        let _ = db.execute("ROLLBACK");
        //        error = true
        //    }
        //}
        //if !error {
        //    if let Err(_) = db.execute(sqlouts){
        //        let _ = db.execute("ROLLBACK");
        //        error = true;
        //    }
        //}
        let _ = db.execute("COMMIT");
        Ok(Response::new(full("thx")))
} 
fn create_database(db: Connection){
    info!("database sanity check");
    let _ = db.execute("CREATE TABLE IF NOT EXISTS tbl_tx      (txid PRIMARY KEY, wtxid, ntxid, tx, locktime integer, network, network_fees, reqid, our_fees, our_address, status integer DEFAULT 0);");
    let _ = db.execute("CREATE TABLE IF NOT EXISTS tbl_input   (txid, in_txid,in_vout, spend_txidi);");
    let _ = db.execute("CREATE TABLE IF NOT EXISTS tbl_output  (txid, script_pubkey, address, amount);");

    let _ = db.execute("CREATE UNIQUE INDEX idx_tbl_input   ON(txid, txid,in_txid,in_vout)");

}



fn match_uri<'a>(path: &str, uri: &'a str) -> Option<&'a str> {
    let re = Regex::new(path).unwrap();
    if let Some(captures) = re.captures(uri) {
        if let Some(param) = captures.name("param") {
            return Some(param.as_str());
        }
    }
    None
}

/// This is our service handler. It receives a Request, routes on its
/// path, and returns a Future of a Response.

async fn echo(
    req: Request<hyper::body::Incoming>,
    cfg: &MyConfig,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {

    let mut not_found = Response::new(empty());
    *not_found.status_mut() = StatusCode::NOT_FOUND;
    let mut ret: Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> = Ok(not_found);

    let uri = req.uri().path().to_string();
    //dbg!(&req);
    dbg!(&uri);
    match req.method() {
        // Serve some instructions at /
        &Method::POST => {
            let whole_body = req.collect().await?.to_bytes();
            if let Some(param) = match_uri(r"^?/?(?P<param>[^/]?+)?/pushtxs$",uri.as_str()) {
                //let whole_body = collect_body(req,512_000).await?;
                ret = echo_push(&whole_body,cfg,param).await;
            }
            if uri=="/searchtx"{
                //let whole_body = collect_body(req,64).await?;
                ret = echo_search(&whole_body,cfg).await;
            }
            ret
        }
        &Method::GET => {
            if let Some(param) = match_uri(r"^?/?(?P<param>[^/]?+)?/info$",uri.as_str()) {
                ret = echo_info(param,cfg).await;
            }
            ret
        }

        // Return the 404 Not Found for other routes.
        _ => ret
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let file = confy::get_configuration_file_path("bal-server",None).expect("Error while getting path");
    info!("The configuration file path is: {:#?}", file);
    let cfg: Arc<MyConfig> = Arc::new(confy::load("bal-server",None).expect("cant_load"));
    let db = sqlite::open(&cfg.db_file).unwrap();
    create_database(db);
    {
        //let cfg = Arc::clone(&cfg);
        //thread::spawn(move|| {
            //let cfg = Arc::clone(&cfg);
            //let file = cfg.requests_file.to_string();
            //loop{
            //        let input = File::open(&file)?;
            //        let reader = BufReader::new(input);


            //        for line in lines.flatten(){
            //           // println!("{}",line);
            //        }
                 
            //thread::sleep(Duration::from_secs(2));
            //}
        //});
    }


    let addr = cfg.bind_address.to_string();
    info!("bind address:{}",addr);
    let addr: IpAddr = addr.parse()?;

    let listener = TcpListener::bind((addr,cfg.bind_port)).await?;
    info!("Listening on http://{}:{}", addr,cfg.bind_port);
            
    

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        
       tokio::task::spawn({
            let cfg = Arc::clone(&cfg);
            async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(io, service_fn(|req: Request<hyper::body::Incoming>| async {
                        echo(req,&cfg).await
                    }))
                    .await
                {
                    error!("Error serving connection: {:?}", err);
                }

            }
        });
    }
}
