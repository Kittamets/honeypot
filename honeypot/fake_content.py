"""
All fake content served by the honeypot.

Everything here is deliberately designed to look like a real legacy intranet
server from ~2009-2013, leaking credentials and sensitive configuration.
None of the passwords, IPs, or keys correspond to any real system.
"""

import json


# ─────────────────────────────────────────────────────────────────────────────
# Fake static files
# ─────────────────────────────────────────────────────────────────────────────

FAKE_ENV = """\
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:K3d8pVqR7mN2xT9wL5sJ1cY6hF4aE0bI8gQnMpZs

DB_CONNECTION=mysql
DB_HOST=192.168.1.10
DB_PORT=3306
DB_DATABASE=intranet_dms
DB_USERNAME=dms_app
DB_PASSWORD=Dms@2011!Prod#9x

MAIL_DRIVER=smtp
MAIL_HOST=mail.corp.local
MAIL_PORT=587
MAIL_USERNAME=noreply@corp.local
MAIL_PASSWORD=M@ilP@ss2010!

REDIS_HOST=192.168.1.15
REDIS_PORT=6379

LDAP_HOST=192.168.1.5
LDAP_PORT=389
LDAP_BIND_DN=cn=svc-dms,ou=service,dc=corp,dc=local
LDAP_BIND_PASSWORD=LdapSvc!2009#Prod

SECRET_KEY=7f4d2e9a1b8c3f6e5d4c2b1a9f8e7d6c5b4a3f2e
ADMIN_EMAIL=admin@corp.local
BACKUP_PATH=\\\\nas01\\backups\\intranet
API_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
"""

FAKE_CONFIG_PHP = """\
<?php
// Database Configuration
// Last modified: 2012-11-03 by admin

define('DB_HOST',     '192.168.1.10');
define('DB_USER',     'dms_app');
define('DB_PASS',     'Dms@2011!Prod#9x');
define('DB_NAME',     'intranet_dms');

// Application Settings
define('APP_NAME',    'Corporate Document Management System');
define('APP_VERSION', '2.1.4');
define('DEBUG_MODE',  false);
define('SESSION_TIMEOUT', 3600);

// File Storage
define('UPLOAD_PATH', 'D:\\\\intranet\\\\uploads\\\\');
define('BACKUP_PATH', '\\\\\\\\nas01\\\\backups\\\\intranet\\\\');
define('MAX_FILE_SIZE', 52428800);  // 50 MB

// LDAP / Active Directory
define('LDAP_SERVER',    '192.168.1.5');
define('LDAP_PORT',       389);
define('LDAP_BIND_USER', 'cn=svc-dms,ou=service,dc=corp,dc=local');
define('LDAP_BIND_PASS', 'LdapSvc!2009#Prod');
define('LDAP_BASE_DN',   'dc=corp,dc=local');

// Email
define('SMTP_HOST', 'mail.corp.local');
define('SMTP_PORT',  587);
define('SMTP_USER', 'noreply@corp.local');
define('SMTP_PASS', 'M@ilP@ss2010!');
define('ADMIN_EMAIL', 'admin@corp.local');

// Security
define('ENCRYPTION_KEY', '7f4d2e9a1b8c3f6e5d4c2b1a9f8e7d6c');
define('HASH_SALT',      'c0rp!ntr@n3t#s@lt2009');

// API Keys
define('REPORTING_API_KEY', 'a7f3c9e2b4d6f8a0c2e4b6d8f0a2c4e6');
?>
"""

FAKE_SQL_DUMP = """\
-- MySQL dump 10.13  Distrib 5.1.73, for Win32 (ia32)
--
-- Host: 192.168.1.10    Database: intranet_dms
-- Server version: 5.1.73
-- Generation Time: Feb 01, 2013 at 03:00 AM

/*!40101 SET NAMES utf8 */;
/*!40014 SET FOREIGN_KEY_CHECKS=0 */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id`          int(11)      NOT NULL AUTO_INCREMENT,
  `username`    varchar(50)  NOT NULL,
  `password`    varchar(128) NOT NULL,
  `email`       varchar(100) DEFAULT NULL,
  `full_name`   varchar(100) DEFAULT NULL,
  `role`        enum('admin','manager','user','viewer') DEFAULT 'user',
  `last_login`  timestamp    NULL,
  `created_at`  timestamp    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=52 DEFAULT CHARSET=utf8;

INSERT INTO `users` VALUES
  (1,'admin',     '$apr1$Gh2k9lPq$X8mN3fK7wY5jT2sR1vD4e.','admin@corp.local','System Administrator','admin',  '2013-02-10 08:34:22','2009-03-15 08:00:00'),
  (2,'jsmith',    '$apr1$Rt7p2mKl$N5qX8wF3sY1jT9vR2eD6b.','j.smith@corp.local','John Smith',         'manager','2013-02-09 17:12:01','2010-01-22 09:15:00'),
  (3,'mjohnson',  '$apr1$Wq5n8kPr$L2xT7mF4sY0jK9vN3eD1a.','m.johnson@corp.local','Mary Johnson',     'user',   '2013-01-28 10:05:44','2010-03-10 11:30:00'),
  (4,'bwilliams', '$apr1$Ym3p7nKs$T8qX2wF5sY6jN1vR4eD9c.','b.williams@corp.local','Bob Williams',    'admin',  '2013-02-08 14:20:33','2010-06-05 14:20:00'),
  (5,'svc_backup','$apr1$Zn2q5mPt$R9xT3wF8sK4jL7vN0eD2b.','',                'Backup Service',       'viewer', '2013-02-01 03:00:00','2011-01-01 00:00:00');

--
-- Table structure for table `documents`
--

DROP TABLE IF EXISTS `documents`;
CREATE TABLE `documents` (
  `id`             int(11)      NOT NULL AUTO_INCREMENT,
  `filename`       varchar(255) NOT NULL,
  `filepath`       varchar(500) NOT NULL,
  `owner_id`       int(11)      DEFAULT NULL,
  `classification` enum('public','internal','confidential','restricted') DEFAULT 'internal',
  `created_at`     timestamp    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1842 DEFAULT CHARSET=utf8;

--
-- Table structure for table `api_keys`
--

DROP TABLE IF EXISTS `api_keys`;
CREATE TABLE `api_keys` (
  `id`           int(11)      NOT NULL AUTO_INCREMENT,
  `service_name` varchar(100) NOT NULL,
  `api_key`      varchar(255) NOT NULL,
  `created_at`   timestamp    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `api_keys` VALUES
  (1,'internal-reporting','a7f3c9e2b4d6f8a0c2e4b6d8f0a2c4e6','2011-05-01 00:00:00'),
  (2,'hr-integration',    'b8g4d0f6h2j8l4n0p6r2t8v4x0z6b2d4','2011-08-15 00:00:00'),
  (3,'finance-api',       'c9h5e1g7i3k9m5o1q7s3u9w5y1a7c3e5','2012-01-10 00:00:00');
"""

FAKE_ROBOTS_TXT = """\
User-agent: *
Disallow: /admin/
Disallow: /admin/login
Disallow: /backup/
Disallow: /db_backup.sql
Disallow: /config.php
Disallow: /.env
Disallow: /old-api/
Disallow: /phpmyadmin/
Disallow: /manager/
Disallow: /uploads/
"""

FAKE_API_USERS = [
    {"id": 1, "username": "admin",      "email": "admin@corp.local",      "role": "admin",   "department": "IT",         "last_login": "2013-02-10T08:34:22Z"},
    {"id": 2, "username": "jsmith",     "email": "j.smith@corp.local",    "role": "manager", "department": "Operations", "last_login": "2013-02-09T17:12:01Z"},
    {"id": 3, "username": "mjohnson",   "email": "m.johnson@corp.local",  "role": "user",    "department": "HR",         "last_login": "2013-01-28T10:05:44Z"},
    {"id": 4, "username": "bwilliams", "email": "b.williams@corp.local", "role": "admin",   "department": "Finance",    "last_login": "2013-02-08T14:20:33Z"},
    {"id": 5, "username": "svc_backup", "email": "",                      "role": "viewer",  "department": "IT",         "last_login": "2013-02-01T03:00:00Z"},
]

FAKE_API_CONFIG = {
    "version": "2.1.4",
    "environment": "production",
    "database": {
        "host":     "192.168.1.10",
        "port":     3306,
        "name":     "intranet_dms",
        "user":     "dms_app",
        "password": "Dms@2011!Prod#9x",
    },
    "ldap": {
        "server":        "192.168.1.5",
        "bind_dn":       "cn=svc-dms,ou=service,dc=corp,dc=local",
        "bind_password": "LdapSvc!2009#Prod",
    },
    "features": {
        "document_versioning":  True,
        "email_notifications":  True,
        "audit_logging":        False,
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# HTML page generators
# ─────────────────────────────────────────────────────────────────────────────

_BASE_CSS = """\
body { font-family: Arial, sans-serif; font-size: 12px; background: #f0f0f0; margin: 0; }
.hdr { background: #003366; color: #fff; padding: 10px 16px; }
.hdr h1 { margin: 0; font-size: 18px; }
.hdr small { color: #aac4e0; }
.content { padding: 14px 16px; }
table { width: 100%; border-collapse: collapse; background: #fff; }
th { background: #003366; color: #fff; padding: 6px 8px; text-align: left; }
td { padding: 4px 8px; border-bottom: 1px solid #ddd; }
tr:hover { background: #fffde0; }
a { color: #003366; }
.ftr { font-size: 10px; color: #888; margin-top: 18px; border-top: 1px solid #ccc; padding-top: 6px; }
.err { color: #c00; background: #fee; border: 1px solid #c00; padding: 6px 10px; margin-bottom: 10px; }
.ok  { color: #060; background: #efe; border: 1px solid #060; padding: 6px 10px; margin-bottom: 10px; }
"""


def get_index_html() -> str:
    return f"""\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head>
<title>Corporate Intranet - Document Management System</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<style>{_BASE_CSS}</style>
</head><body>
<div class="hdr">
  <h1>Corporate Intranet &mdash; Document Management System v2.1</h1>
  <small>Server: CORP-INTRANET-OLD01 &nbsp;|&nbsp; Last system check: 2013-02-10</small>
</div>
<div class="content">
<table>
<tr><th>Name</th><th>Last Modified</th><th>Size</th><th>Description</th></tr>
<tr><td><a href="/admin/">[admin]</a></td><td>2013-01-15 09:23</td><td>&mdash;</td><td>Administration Panel</td></tr>
<tr><td><a href="/backup/">[backup]</a></td><td>2013-02-01 03:00</td><td>&mdash;</td><td>System Backups</td></tr>
<tr><td><a href="/uploads/">[uploads]</a></td><td>2013-02-08 11:45</td><td>&mdash;</td><td>Uploaded Documents</td></tr>
<tr><td><a href="/old-api/v1/">[old-api]</a></td><td>2012-06-20 14:30</td><td>&mdash;</td><td>Legacy REST API (deprecated)</td></tr>
<tr><td><a href="/config.php">config.php</a></td><td>2012-11-03 16:55</td><td>4.2 KB</td><td>Application Configuration</td></tr>
<tr><td><a href="/.env">.env</a></td><td>2012-11-03 16:55</td><td>1.1 KB</td><td>Environment Variables</td></tr>
<tr><td><a href="/phpmyadmin/">phpmyadmin</a></td><td>2010-04-22 08:00</td><td>&mdash;</td><td>Database Administration</td></tr>
</table>
<div class="ftr">&copy; 2009&ndash;2013 ACME Corporation. Internal use only.
| IT Department | <a href="mailto:helpdesk@corp.local">helpdesk@corp.local</a></div>
</div>
</body></html>
"""


def get_admin_login_html(error: bool = False) -> str:
    msg = ""
    if error:
        msg = '<div class="err">Invalid username or password. Please try again.</div>'
    return f"""\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head>
<title>Admin Login &mdash; Corporate DMS</title>
<style>
body {{ font-family: Arial, sans-serif; background: #003366; }}
.box {{ width: 360px; margin: 80px auto; background: #fff; padding: 28px 32px; border-radius: 3px; }}
h2 {{ color: #003366; text-align: center; margin: 0 0 4px; }}
h3 {{ color: #666; text-align: center; font-size: 13px; font-weight: normal; margin: 0 0 18px; }}
label {{ display: block; font-size: 12px; color: #444; margin-bottom: 2px; }}
input[type=text], input[type=password] {{
  width: 100%; padding: 7px; margin-bottom: 14px;
  border: 1px solid #bbb; box-sizing: border-box; font-size: 13px; }}
input[type=submit] {{
  width: 100%; padding: 9px; background: #003366; color: #fff;
  border: none; cursor: pointer; font-size: 13px; }}
input[type=submit]:hover {{ background: #004488; }}
small {{ display: block; text-align: center; color: #888; margin-top: 14px; font-size: 11px; }}
.err {{ color:#c00; background:#fee; border:1px solid #c00; padding:6px 8px; margin-bottom:12px; font-size:12px; }}
</style>
</head><body>
<div class="box">
  <h2>Document Management System</h2>
  <h3>Administrator Login</h3>
  {msg}
  <form method="POST" action="/admin/login">
    <label>Username:</label>
    <input type="text" name="username" autocomplete="off">
    <label>Password:</label>
    <input type="password" name="password">
    <input type="submit" value="Login">
  </form>
  <small>Corporate Intranet DMS v2.1 &copy; 2009&ndash;2013</small>
  <small>Problems? <a href="mailto:helpdesk@corp.local">helpdesk@corp.local</a></small>
</div>
</body></html>
"""


def get_admin_dashboard_html() -> str:
    """Shown after any credential submission — maximises dwell time."""
    return f"""\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head>
<title>Admin Dashboard &mdash; Corporate DMS</title>
<style>{_BASE_CSS}
.stat {{ display:inline-block; background:#003366; color:#fff; padding:14px 22px;
         margin:6px; text-align:center; min-width:120px; }}
.stat b {{ display:block; font-size:24px; }}
</style>
</head><body>
<div class="hdr">
  <h1>Admin Dashboard &mdash; Document Management System v2.1</h1>
  <small>Logged in as: <b>admin</b> &nbsp;|&nbsp; CORP-INTRANET-OLD01</small>
</div>
<div class="content">
<p>
  <span class="stat"><b>1,841</b> Documents</span>
  <span class="stat"><b>51</b> Users</span>
  <span class="stat"><b>142 GB</b> Storage Used</span>
  <span class="stat"><b>3</b> Pending Approvals</span>
</p>
<h3>Quick Links</h3>
<table style="width:50%">
  <tr><th>Section</th><th>Link</th></tr>
  <tr><td>User Management</td><td><a href="/admin/users">Manage Users</a></td></tr>
  <tr><td>Database</td><td><a href="/phpmyadmin/">phpMyAdmin</a></td></tr>
  <tr><td>System Config</td><td><a href="/config.php">config.php</a></td></tr>
  <tr><td>Backups</td><td><a href="/backup/">Backup Directory</a></td></tr>
  <tr><td>Legacy API</td><td><a href="/old-api/v1/users">User API</a></td></tr>
</table>
<h3>Recent Activity</h3>
<table>
  <tr><th>Time</th><th>User</th><th>Action</th></tr>
  <tr><td>2013-02-10 08:34</td><td>admin</td><td>Logged in</td></tr>
  <tr><td>2013-02-09 17:12</td><td>jsmith</td><td>Uploaded: Q4_Financial_Report_DRAFT.xlsx</td></tr>
  <tr><td>2013-02-09 14:05</td><td>bwilliams</td><td>Accessed: HR_Salary_2013.xlsx (CONFIDENTIAL)</td></tr>
  <tr><td>2013-02-08 11:30</td><td>mjohnson</td><td>Updated employee record: ID 2847</td></tr>
</table>
<div class="ftr">&copy; 2009&ndash;2013 ACME Corporation. Internal use only.</div>
</div>
</body></html>
"""


def get_admin_users_html() -> str:
    return f"""\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head>
<title>User Management &mdash; Corporate DMS</title>
<style>{_BASE_CSS}</style>
</head><body>
<div class="hdr"><h1>User Management</h1><small>CORP-INTRANET-OLD01</small></div>
<div class="content">
<table>
<tr><th>ID</th><th>Username</th><th>Full Name</th><th>Email</th><th>Role</th><th>Last Login</th></tr>
<tr><td>1</td><td>admin</td><td>System Administrator</td><td>admin@corp.local</td><td>admin</td><td>2013-02-10 08:34</td></tr>
<tr><td>2</td><td>jsmith</td><td>John Smith</td><td>j.smith@corp.local</td><td>manager</td><td>2013-02-09 17:12</td></tr>
<tr><td>3</td><td>mjohnson</td><td>Mary Johnson</td><td>m.johnson@corp.local</td><td>user</td><td>2013-01-28 10:05</td></tr>
<tr><td>4</td><td>bwilliams</td><td>Bob Williams</td><td>b.williams@corp.local</td><td>admin</td><td>2013-02-08 14:20</td></tr>
<tr><td>5</td><td>svc_backup</td><td>Backup Service</td><td>&mdash;</td><td>viewer</td><td>2013-02-01 03:00</td></tr>
</table>
<div class="ftr">&copy; 2009&ndash;2013 ACME Corporation.</div>
</div></body></html>
"""


def get_backup_listing_html() -> str:
    return """\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head>
<title>Index of /backup &mdash; CORP-INTRANET-OLD01</title>
<style>body{font-family:monospace;font-size:13px;padding:20px;} h1{font-size:16px;} a{color:#00c;} hr{border:1px solid #aaa;}</style>
</head><body>
<h1>Index of /backup</h1>
<pre>
      <a href="?C=N&amp;O=D">Name</a>                            <a href="?C=M&amp;O=A">Last modified</a>       <a href="?C=S&amp;O=A">Size</a>
<hr>
      <a href="/">[Parent Directory]</a>                              -
      <a href="/db_backup.sql">db_backup.sql</a>                   2013-02-01 03:00   18M
      <a href="/backup.zip">backup_20130201.zip</a>             2013-02-01 03:15  142M
      backup_20130101/                2013-01-01 03:00    -
      backup_20121201/                2012-12-01 03:00    -
      <a href="#">configs_20121103.tar.gz</a>         2012-11-03 16:55  2.4M
<hr></pre>
<address>Apache/2.2.14 (Win32) Server at CORP-INTRANET-OLD01 Port 80</address>
</body></html>
"""


def get_phpmyadmin_html() -> str:
    return """\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head>
<title>phpMyAdmin 3.3.10.4</title>
<style>
body{font-family:sans-serif;background:#d0d0d0;}
.box{background:#fff;width:380px;margin:60px auto;padding:22px;border:1px solid #bbb;}
label{font-size:12px;display:block;margin-bottom:2px;}
input{width:100%;padding:5px;margin-bottom:12px;box-sizing:border-box;border:1px solid #aaa;}
input[type=submit]{background:#4a6984;color:#fff;border:none;cursor:pointer;padding:7px;}
small{font-size:11px;color:#666;}
</style>
</head><body>
<div class="box">
  <p><b>phpMyAdmin</b></p>
  <form method="POST" action="/phpmyadmin/index.php">
    <input type="hidden" name="token" value="374e19b22f0ec6d3a0a6f1b2b44aa2c9">
    <label>Username:</label><input type="text" name="pma_username">
    <label>Password:</label><input type="password" name="pma_password">
    <label>Server:</label><input type="text" name="server" value="192.168.1.10">
    <input type="submit" value="Go">
  </form>
  <br><small>phpMyAdmin 3.3.10.4 &nbsp;|&nbsp; MySQL: 5.1.73 &nbsp;|&nbsp; PHP: 5.2.17</small>
</div>
</body></html>
"""


def get_tomcat_html() -> str:
    return """\
<!DOCTYPE html>
<html><head><title>401 Unauthorized</title></head>
<body>
<h1>HTTP Status 401 - Unauthorized</h1>
<hr noshade>
<p><b>type</b> Status report</p>
<p><b>message</b> <u>Unauthorized</u></p>
<p><b>description</b> <u>This request requires HTTP authentication.</u></p>
<hr noshade>
<h3>Apache Tomcat/6.0.29</h3>
</body></html>
"""


def get_404_html(path: str) -> str:
    return f"""\
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL {path} was not found on this server.</p>
<hr>
<address>Apache/2.2.14 (Win32) Server at CORP-INTRANET-OLD01 Port 80</address>
</body></html>
"""
