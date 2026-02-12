//! Protocol module registry. Each `pub mod` below is a self-registering module.
//! Adding a module = add its file + one `pub mod` line here.
//!
//! `http_util` is a shared helper (not a protocol) used by the HTTP modules.

pub mod http_util;

pub mod adam6500;
pub mod afp;
pub mod asterisk;
pub mod cisco;
pub mod cobaltstrike;
pub mod cvs;
pub mod firebird;
pub mod ftp;
pub mod http_basic;
pub mod http_form;
pub mod http_proxy;
pub mod icq;
pub mod imap;
pub mod irc;
pub mod ldap;
pub mod memcached;
pub mod mongodb;
pub mod mqtt;
pub mod mssql;
pub mod mysql;
pub mod ncp;
pub mod nntp;
pub mod oracle;
pub mod pcanywhere;
pub mod pcnfs;
pub mod pop3;
pub mod postgresql;
pub mod radmin2;
pub mod rdp;
pub mod redis;
pub mod rexec;
pub mod rlogin;
pub mod rpcap;
pub mod rsh;
pub mod rtsp;
pub mod s7_300;
pub mod sap_r3;
pub mod sip;
pub mod smb;
pub mod smtp;
pub mod snmp;
pub mod socks5;
pub mod ssh;
pub mod svn;
pub mod teamspeak;
pub mod telnet;
pub mod time;
pub mod vmauthd;
pub mod vnc;
pub mod xmpp;
