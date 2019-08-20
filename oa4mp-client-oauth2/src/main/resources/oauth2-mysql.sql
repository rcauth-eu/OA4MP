/*
   This script will create the tables for a basic oa4mp install. Since MySQL has *no* variable
   support, everything is hard-coded. if you want something other than the default names and
   then edit the file.

   Also, the default timestamp must all be CURRENT_TIME. This is crucial to do
   or the default for MariaDB if no default is specified is then to update each
   timestamp field on update, effectively rendering the field merely a timestamp
   of the last update, rather than, sayd the original creation timestamp.
*/

/*
Usage: Log in as an administrator (such as root) that can create the user, if need be.

CREATE USER 'oa4mp-client'@'localhost' IDENTIFIED BY 'PASSWORD';

Run the rest of this script.
*/

CREATE DATABASE oauth DEFAULT CHARACTER SET utf8;
USE oauth;


CREATE TABLE assets (
  identifier       VARCHAR(255) PRIMARY KEY,
  private_key      TEXT,
  username         TEXT,
  redirect_uri     TEXT,
  certificate      TEXT,
  refresh_token    TEXT,
  access_token     TEXT,
  nonce            TEXT,
  state            TEXT,
  issuedat         TIMESTAMP,
  refresh_lifetime BIGINT,
  cert_req         TEXT,
  token            TEXT,
  creation_ts      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


COMMIT;

# Set permissions.

GRANT ALL PRIVILEGES ON assets TO 'oa4mp-client'@'localhost';

COMMIT;
