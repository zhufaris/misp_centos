#!/usr/bin/env bash
debug () {
  echo -e "${RED}Next step:${NC} ${GREEN}$1${NC}" > /dev/tty
  if [[ ! -z ${DEBUG} ]]; then
    NO_PROGRESS=1
    echo -e "${RED}Debug Mode${NC}, press ${LBLUE}enter${NC} to continue..." > /dev/tty
    exec 3>&1
    read
  else
    # [Set up conditional redirection](https://stackoverflow.com/questions/8756535/conditional-redirection-in-bash)
    #exec 3>&1 &>/dev/null
    :
  fi
}

prepareUser() {
  sudo useradd $MISP_USER
}

enableEPEL () {
  sudo yum install dnf -y
  sudo dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
  sudo dnf install http://rpms.remirepo.net/enterprise/remi-release-7.rpm -y
  sudo dnf install yum-utils policycoreutils-python -y
  sudo yum-config-manager --enable remi-php74
}

yumInstallCoreDeps7 () {
  # Install the dependencies:
  sudo dnf install gcc git zip unzip \
                   mod_ssl \
                   moreutils \
                   redis \
                   libxslt-devel zlib-devel ssdeep-devel -y

  # Enable and start redis
  sudo systemctl enable --now redis.service

  # Install MariaDB
  sudo dnf install wget -y
  wget https://downloads.mariadb.com/MariaDB/mariadb_repo_setup && chmod +x mariadb_repo_setup && sudo ./mariadb_repo_setup && rm mariadb_repo_setup
  sudo dnf install MariaDB-server -y

  # Install PHP 7.4 from Remi's repo, see https://rpms.remirepo.net/enterprise/7/php74/x86_64/repoview/
  sudo dnf install php php-fpm php-devel \
                   php-mysqlnd \
                   php-mbstring \
                   php-xml \
                   php-bcmath \
                   php-opcache \
                   php-zip \
                   php-pear \
                   php-brotli \
                   php-intl \
                   php-gd -y

  # cake has php baked in, thus we link to it if necessary.
  [[ ! -e "/usr/bin/php" ]] && sudo ln -s /usr/bin/php74 /usr/bin/php

  # Python 3.6 is now available in RHEL 7.7 base
  sudo dnf install python3 python3-devel python3-virtualenv -y

  sudo systemctl enable --now php-fpm.service
}

installEntropyRHEL () {
  # GPG needs lots of entropy, haveged provides entropy
  # /!\ Only do this if you're not running rngd to provide randomness and your kernel randomness is not sufficient.
  sudo dnf install haveged -y
  sudo systemctl enable --now haveged.service
}

installCoreRHEL7 () {
  # Download MISP using git in the $PATH_TO_MISP directory.
  sudo rm -rf $(dirname $PATH_TO_MISP)
  sudo mkdir -p $(dirname $PATH_TO_MISP)
  sudo chown $WWW_USER:$WWW_USER $(dirname $PATH_TO_MISP)
  cd $(dirname $PATH_TO_MISP)
  $SUDO_WWW git clone https://github.com/MISP/MISP.git
  cd $PATH_TO_MISP

  # Fetch submodules
  $SUDO_WWW git submodule sync
  $SUDO_WWW git submodule update --init --recursive
  # Make git ignore filesystem permission differences for submodules
  $SUDO_WWW git submodule foreach --recursive git config core.filemode false
  # Make git ignore filesystem permission differences
  $SUDO_WWW git config core.filemode false

  # Create a python3 virtualenv
  [[ -e $(which virtualenv-3 2>/dev/null) ]] && $SUDO_WWW virtualenv-3 -p python3 $PATH_TO_MISP/venv
  [[ -e $(which virtualenv 2>/dev/null) ]] && $SUDO_WWW virtualenv -p python3 $PATH_TO_MISP/venv
  $SUDO_WWW python3 -m venv $PATH_TO_MISP/venv
  sudo mkdir /usr/share/httpd/.cache
  sudo chown $WWW_USER:$WWW_USER /usr/share/httpd/.cache
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U pip setuptools

  # If you umask is has been changed from the default, it is a good idea to reset it to 0022 before installing python modules
  UMASK=$(umask)
  umask 0022

  # install python-stix dependencies
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install ordered-set python-dateutil six weakrefmethod

  # install zmq
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U zmq

  # install redis
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U redis

  # install magic, pydeep, lief
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U python-magic git+https://github.com/kbandla/pydeep.git plyara lief

  # install PyMISP
  cd $PATH_TO_MISP/PyMISP
  $SUDO_WWW $PATH_TO_MISP/venv/bin/pip install -U .

  # FIXME: Remove libfaup etc once the egg has the library baked-in
  # BROKEN: This needs to be tested on RHEL/CentOS
  sudo dnf install libcaca-devel cmake3 -y
  cd /tmp
  [[ ! -d "faup" ]] && $SUDO_CMD git clone https://github.com/stricaud/faup.git faup
  [[ ! -d "gtcaca" ]] && $SUDO_CMD git clone https://github.com/stricaud/gtcaca.git gtcaca
  sudo chown -R ${MISP_USER}:${MISP_USER} faup gtcaca
  cd gtcaca
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake3 .. && $SUDO_CMD make
  sudo make install
  cd ../../faup
  $SUDO_CMD mkdir -p build
  cd build
  $SUDO_CMD cmake3 .. && $SUDO_CMD make
  sudo make install
  sudo ldconfig

  # Enable dependencies detection in the diagnostics page
  # This allows MISP to detect GnuPG, the Python modules' versions and to read the PHP settings.
  echo "env[PATH] = /usr/local/bin:/usr/bin:/bin" |sudo tee -a ${PHP_BASE}/php-fpm.d/www.conf
  sudo sed -i.org -e 's/^;\(clear_env = no\)/\1/' ${PHP_BASE}/php-fpm.d/www.conf
  sudo sed -i.org -e 's/^\(listen =\) \/run\/php-fpm\/www\.sock/\1 127.0.0.1:9000/' ${PHP_BASE}/php-fpm.d/www.conf

  sudo systemctl restart php-fpm.service
  umask $UMASK
}

installCake_RHEL () {
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP
  sudo mkdir /usr/share/httpd/.composer
  sudo chown $WWW_USER:$WWW_USER /usr/share/httpd/.composer
  cd $PATH_TO_MISP/app
  $SUDO_WWW php composer.phar require kamisama/cake-resque
  $SUDO_WWW php composer.phar config vendor-dir Vendor
  $SUDO_WWW php composer.phar install --no-dev

  sudo dnf install php-pecl-redis php-pecl-ssdeep php-pecl-gnupg -y

  sudo systemctl restart php-fpm.service

  # If you have not yet set a timezone in php.ini
  echo 'date.timezone = "Asia/Singapore"' |sudo tee /etc/php-fpm.d/timezone.ini
  sudo ln -s ../php-fpm.d/timezone.ini /etc/php.d/99-timezone.ini

  # Recommended: Change some PHP settings in /etc/opt/remi/php74/php.ini
  max_execution_time=300
  memory_limit=2048M
  upload_max_filesize=50M
  post_max_size=50M
  for key in upload_max_filesize post_max_size max_execution_time max_input_time memory_limit
  do
      sudo sed -i "s/^\($key\).*/\1 = $(eval echo \${$key})/" $PHP_INI
  done
  sudo sed -i "s/^\(session.sid_length\).*/\1 = $(eval echo \${session0sid_length})/" $PHP_INI
  sudo sed -i "s/^\(session.use_strict_mode\).*/\1 = $(eval echo \${session0use_strict_mode})/" $PHP_INI
  sudo systemctl restart php-fpm.service

  # To use the scheduler worker for scheduled tasks, do the following:
  sudo cp -fa $PATH_TO_MISP/INSTALL/setup/config.php $PATH_TO_MISP/app/Plugin/CakeResque/Config/config.php
}

permissions_RHEL7 () {
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP
  ## ? chown -R root:$WWW_USER $PATH_TO_MISP
  sudo find $PATH_TO_MISP -type d -exec chmod g=rx {} \;
  sudo chmod -R g+r,o= $PATH_TO_MISP
  ## **Note :** For updates through the web interface to work, apache must own the $PATH_TO_MISP folder and its subfolders as shown above, which can lead to security issues. If you do not require updates through the web interface to work, you can use the following more restrictive permissions :
  sudo chmod -R 750 $PATH_TO_MISP
  sudo chmod -R g+xws $PATH_TO_MISP/app/tmp
  sudo chmod -R g+ws $PATH_TO_MISP/app/files
  sudo chmod -R g+ws $PATH_TO_MISP/app/files/scripts/tmp
  sudo chmod -R g+rw $PATH_TO_MISP/venv
  sudo chmod -R g+rw $PATH_TO_MISP/.git
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/files
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/files/terms
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/files/scripts/tmp
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Plugin/CakeResque/tmp
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Config
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/tmp
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/webroot/img/orgs
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/app/webroot/img/custom
}

prepareDB_RHEL () {
  sudo systemctl enable --now mariadb.service
  echo [mysqld] |sudo tee /etc/my.cnf.d/bind-address.cnf
  echo bind-address=127.0.0.1 |sudo tee -a /etc/my.cnf.d/bind-address.cnf
  sudo systemctl restart mariadb

  # Kill the anonymous users
  sudo mysql -h $DBHOST -e "DROP USER IF EXISTS ''@'localhost'"
  # Because our hostname varies we'll use some Bash magic here.
  sudo mysql -h $DBHOST -e "DROP USER IF EXISTS ''@'$(hostname)'"
  # Kill off the demo database
  sudo mysql -h $DBHOST -e "DROP DATABASE IF EXISTS test"
  # No root remote logins
  sudo mysql -h $DBHOST -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
  # Make sure that NOBODY can access the server without a password
  sudo mysqladmin -h $DBHOST -u "${DBUSER_ADMIN}" password "${DBPASSWORD_ADMIN}"
  # Make our changes take effect
  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "FLUSH PRIVILEGES"

  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "CREATE DATABASE ${DBNAME};"
  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "CREATE USER '${DBUSER_MISP}'@'localhost' IDENTIFIED BY '${DBPASSWORD_MISP}';"
  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "GRANT USAGE ON *.* to '${DBUSER_MISP}'@'localhost';"
  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "GRANT ALL PRIVILEGES on ${DBNAME}.* to '${DBUSER_MISP}'@'localhost';"
  sudo mysql -h $DBHOST -u "${DBUSER_ADMIN}" -p"${DBPASSWORD_ADMIN}" -e "FLUSH PRIVILEGES;"
  # Import the empty MISP database from MYSQL.sql
  ${SUDO_WWW} cat ${PATH_TO_MISP}/INSTALL/MYSQL.sql | mysql -h $DBHOST -u "${DBUSER_MISP}" -p"${DBPASSWORD_MISP}" ${DBNAME}
}
# <snippet-end 1_prepareDB_RHEL.sh>

apacheConfig_RHEL7 () {
  # Now configure your apache server with the DocumentRoot $PATH_TO_MISP/app/webroot/
  # A sample vhost can be found in $PATH_TO_MISP/INSTALL/apache.misp.centos7
  sudo mkdir -p /etc/httpd/conf.d/
  sudo cp $PATH_TO_MISP/INSTALL/apache.misp.centos7.ssl /etc/httpd/conf.d/misp.ssl.conf
  #sudo sed -i "s/SetHandler/\#SetHandler/g" /etc/httpd/conf.d/misp.ssl.conf
  sudo rm /etc/httpd/conf.d/ssl.conf
  sudo chmod 644 /etc/httpd/conf.d/misp.ssl.conf
  sudo sed -i '/Listen 443/d' /etc/httpd/conf/httpd.conf
  sudo sed -i '/Listen 80/a Listen 443' /etc/httpd/conf/httpd.conf

  # If a valid SSL certificate is not already created for the server, create a self-signed certificate:
  echo "The Common Name used below will be: ${OPENSSL_CN}"
  # This will take a rather long time, be ready. (13min on a VM, 8GB Ram, 1 core)
  if [[ ! -e "/etc/pki/tls/certs/dhparam.pem" ]]; then
    sudo openssl dhparam -out /etc/pki/tls/certs/dhparam.pem 4096
  fi
  sudo openssl genrsa -des3 -passout pass:xxxx -out /tmp/misp.local.key 4096
  sudo openssl rsa -passin pass:xxxx -in /tmp/misp.local.key -out /etc/pki/tls/private/misp.local.key
  sudo rm /tmp/misp.local.key
  sudo openssl req -new -subj "/C=${OPENSSL_C}/ST=${OPENSSL_ST}/L=${OPENSSL_L}/O=${OPENSSL_O}/OU=${OPENSSL_OU}/CN=${OPENSSL_CN}/emailAddress=${OPENSSL_EMAILADDRESS}" -key /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.csr
  sudo openssl x509 -req -days 365 -in /etc/pki/tls/certs/misp.local.csr -signkey /etc/pki/tls/private/misp.local.key -out /etc/pki/tls/certs/misp.local.crt
  sudo ln -s /etc/pki/tls/certs/misp.local.csr /etc/pki/tls/certs/misp-chain.crt
  cat /etc/pki/tls/certs/dhparam.pem |sudo tee -a /etc/pki/tls/certs/misp.local.crt

  sudo systemctl restart httpd.service

  # Since SELinux is enabled, we need to allow httpd to write to certain directories
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/terms
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/scripts/tmp
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Plugin/CakeResque/tmp
  sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Console/cake
  sudo sh -c "chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Console/worker/*.sh"
  sudo sh -c "chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/*.py"
  sudo sh -c "chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/files/scripts/*/*.py"
  sudo chcon -t httpd_sys_script_exec_t $PATH_TO_MISP/app/Vendor/pear/crypt_gpg/scripts/crypt-gpg-pinentry
  sudo sh -c "chcon -R -t bin_t $PATH_TO_MISP/venv/bin/*"
  sudo find $PATH_TO_MISP/venv -type f -name "*.so*" -or -name "*.so.*" | xargs sudo chcon -t lib_t
  # Only run these if you want to be able to update MISP from the web interface
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/.git
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/tmp
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Lib
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Config
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/webroot/img/orgs
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/webroot/img/custom
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/files/scripts/mispzmq
}

firewall_RHEL () {
  # Allow httpd to connect to the redis server and php-fpm over tcp/ip
  sudo setsebool -P httpd_can_network_connect on

  # Allow httpd to send emails from php
  sudo setsebool -P httpd_can_sendmail on

  # Enable and start the httpd service
  sudo systemctl enable --now httpd.service

  # Open a hole in the iptables firewall
  sudo firewall-cmd --zone=public --add-port=80/tcp --permanent
  sudo firewall-cmd --zone=public --add-port=443/tcp --permanent
  sudo firewall-cmd --reload
}

logRotation_RHEL () {
  # MISP saves the stdout and stderr of its workers in $PATH_TO_MISP/app/tmp/logs
  # To rotate these logs install the supplied logrotate script:

  sudo cp $PATH_TO_MISP/INSTALL/misp.logrotate /etc/logrotate.d/misp
  sudo chmod 0640 /etc/logrotate.d/misp

  # Now make logrotate work under SELinux as well
  # Allow logrotate to modify the log files
  sudo semanage fcontext -a -t httpd_sys_rw_content_t "$PATH_TO_MISP(/.*)?"
  sudo semanage fcontext -a -t httpd_log_t "$PATH_TO_MISP/app/tmp/logs(/.*)?"
  sudo chcon -R -t httpd_log_t $PATH_TO_MISP/app/tmp/logs
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/app/tmp/logs
  # Impact of the following: ?!?!?!!?111
  ##sudo restorecon -R $PATH_TO_MISP

  # Allow logrotate to read /var/www
  sudo checkmodule -M -m -o /tmp/misplogrotate.mod $PATH_TO_MISP/INSTALL/misplogrotate.te
  sudo semodule_package -o /tmp/misplogrotate.pp -m /tmp/misplogrotate.mod
  sudo semodule -i /tmp/misplogrotate.pp
}

configMISP_RHEL () {
  # There are 4 sample configuration files in $PATH_TO_MISP/app/Config that need to be copied
  $SUDO_WWW cp -a $PATH_TO_MISP/app/Config/bootstrap.default.php $PATH_TO_MISP/app/Config/bootstrap.php
  $SUDO_WWW cp -a $PATH_TO_MISP/app/Config/database.default.php $PATH_TO_MISP/app/Config/database.php
  $SUDO_WWW cp -a $PATH_TO_MISP/app/Config/core.default.php $PATH_TO_MISP/app/Config/core.php
  $SUDO_WWW cp -a $PATH_TO_MISP/app/Config/config.default.php $PATH_TO_MISP/app/Config/config.php

  echo "<?php
  class DATABASE_CONFIG {
          public \$default = array(
                  'datasource' => 'Database/Mysql',
                  //'datasource' => 'Database/Postgres',
                  'persistent' => false,
                  'host' => '$DBHOST',
                  'login' => '$DBUSER_MISP',
                  'port' => 3306, // MySQL & MariaDB
                  //'port' => 5432, // PostgreSQL
                  'password' => '$DBPASSWORD_MISP',
                  'database' => '$DBNAME',
                  'prefix' => '',
                  'encoding' => 'utf8',
          );
  }" | $SUDO_WWW tee $PATH_TO_MISP/app/Config/database.php

  # Configure the fields in the newly created files:
  # config.php   : baseurl (example: 'baseurl' => 'http://misp',) - don't use "localhost" it causes issues when browsing externally
  # core.php   : Uncomment and set the timezone: `// date_default_timezone_set('UTC');`
  # database.php : login, port, password, database
  # DATABASE_CONFIG has to be filled
  # With the default values provided in section 6, this would look like:
  # class DATABASE_CONFIG {
  #   public $default = array(
  #       'datasource' => 'Database/Mysql',
  #       'persistent' => false,
  #       'host' => 'localhost',
  #       'login' => 'misp', // grant usage on *.* to misp@localhost
  #       'port' => 3306,
  #       'password' => 'XXXXdbpasswordhereXXXXX', // identified by 'XXXXdbpasswordhereXXXXX';
  #       'database' => 'misp', // create database misp;
  #       'prefix' => '',
  #       'encoding' => 'utf8',
  #   );
  #}

  # Important! Change the salt key in $PATH_TO_MISP/app/Config/config.php
  # The admin user account will be generated on the first login, make sure that the salt is changed before you create that user
  # If you forget to do this step, and you are still dealing with a fresh installation, just alter the salt,
  # delete the user from mysql and log in again using the default admin credentials (admin@admin.test / admin)

  # If you want to be able to change configuration parameters from the webinterface:
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/Config/config.php
  sudo chmod 660 $PATH_TO_MISP/app/Config/config.php
  sudo chcon -t httpd_sys_rw_content_t $PATH_TO_MISP/app/Config/config.php

  # Generate a GPG encryption key.
  cat >/tmp/gen-key-script <<EOF
      %echo Generating a default key
      Key-Type: default
      Key-Length: $GPG_KEY_LENGTH
      Subkey-Type: default
      Name-Real: $GPG_REAL_NAME
      Name-Comment: $GPG_COMMENT
      Name-Email: $GPG_EMAIL_ADDRESS
      Expire-Date: 0
      Passphrase: $GPG_PASSPHRASE
      # Do a commit here, so that we can later print "done"
      %commit
      %echo done
EOF

  sudo gpg --homedir $PATH_TO_MISP/.gnupg --batch --gen-key /tmp/gen-key-script
  sudo rm -f /tmp/gen-key-script
  sudo chown -R $WWW_USER:$WWW_USER $PATH_TO_MISP/.gnupg
  sudo chcon -R -t httpd_sys_rw_content_t $PATH_TO_MISP/.gnupg

  # And export the public key to the webroot
  sudo gpg --homedir $PATH_TO_MISP/.gnupg --export --armor $GPG_EMAIL_ADDRESS |sudo tee $PATH_TO_MISP/app/webroot/gpg.asc
  sudo chown $WWW_USER:$WWW_USER $PATH_TO_MISP/app/webroot/gpg.asc

  echo "Admin (root) DB Password: $DBPASSWORD_ADMIN"
  echo "User  (misp) DB Password: $DBPASSWORD_MISP"
}

configWorkersRHEL () {
  echo "[Unit]
  Description=MISP background workers
  After=mariadb.service redis.service php-fpm.service

  [Service]
  Type=forking
  User=$WWW_USER
  Group=$WWW_USER
  ExecStart=$PATH_TO_MISP/app/Console/worker/start.sh
  Restart=always
  RestartSec=10

  [Install]
  WantedBy=multi-user.target" |sudo tee /etc/systemd/system/misp-workers.service

  sudo chmod +x $PATH_TO_MISP/app/Console/worker/start.sh
  sudo systemctl daemon-reload

  sudo systemctl enable --now misp-workers.service
}

coreCAKE () {
  debug "Running core Cake commands to set sane defaults for ${LBLUE}MISP${NC}"
  sudo sed -i '298s/require/\#require/' /var/www/MISP/app/Config/core.php

  # IF you have logged in prior to running this, it will fail but the fail is NON-blocking
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} userInit -q

  # This makes sure all Database upgrades are done, without logging in.
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin runUpdates

  # The default install is Python >=3.6 in a virtualenv, setting accordingly
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.python_bin" "${PATH_TO_MISP}/venv/bin/python"

  # Set default role
  # TESTME: The following seem defunct, please test.
  # ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} setDefaultRole 3

  # Tune global time outs
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Session.autoRegenerate" 0
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Session.timeout" 600
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Session.cookieTimeout" 3600
 
  # Set the default temp dir
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.tmpdir" "${PATH_TO_MISP}/app/tmp"

  # Change base url, either with this CLI command or in the UI
  [[ ! -z ${MISP_BASEURL} ]] && ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Baseurl $MISP_BASEURL
  # example: 'baseurl' => 'https://<your.FQDN.here>',
  # alternatively, you can leave this field empty if you would like to use relative pathing in MISP
  # 'baseurl' => '',
  # The base url of the application (in the format https://www.mymispinstance.com) as visible externally/by other MISPs.
  # MISP will encode this URL in sharing groups when including itself. If this value is not set, the baseurl is used as a fallback.
  [[ ! -z ${MISP_BASEURL} ]] && ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.external_baseurl" ${MISP_BASEURL}

  # Enable GnuPG
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.email" "${GPG_EMAIL_ADDRESS}"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.homedir" "${PATH_TO_MISP}/.gnupg"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.password" "${GPG_PASSPHRASE}"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.obscure_subject" true
  # FIXME: what if we have not gpg binary but a gpg2 one?
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "GnuPG.binary" "$(which gpg)"

  # Enable installer org and tune some configurables
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.host_org_id" 1
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.email" "info@admin.test"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disable_emailing" true --force
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.contact" "info@admin.test"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disablerestalert" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.showCorrelationsOnIndex" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.default_event_tag_collection" 0

  # Provisional Cortex tunes
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_services_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_services_url" "http://127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_services_port" 9000
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_timeout" 120
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_authkey" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_ssl_verify_peer" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_ssl_verify_host" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Cortex_ssl_allow_self_signed" true

  # Various plugin sightings settings
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Sightings_policy" 0
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Sightings_anonymise" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Sightings_anonymise_as" 1
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Sightings_range" 365
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Sightings_sighting_db_enable" false

  # TODO: Fix the below list
  # Set API_Required modules to false
  PLUGS=(Plugin.Enrichment_cuckoo_submit_enabled
         Plugin.Enrichment_vmray_submit_enabled
         Plugin.Enrichment_circl_passivedns_enabled
         Plugin.Enrichment_circl_passivessl_enabled
         Plugin.Enrichment_domaintools_enabled
         Plugin.Enrichment_eupi_enabled
         Plugin.Enrichment_farsight_passivedns_enabled
         Plugin.Enrichment_passivetotal_enabled
         Plugin.Enrichment_passivetotal_enabled
         Plugin.Enrichment_virustotal_enabled
         Plugin.Enrichment_whois_enabled
         Plugin.Enrichment_shodan_enabled
         Plugin.Enrichment_geoip_asn_enabled
         Plugin.Enrichment_geoip_city_enabled
         Plugin.Enrichment_geoip_country_enabled
         Plugin.Enrichment_iprep_enabled
         Plugin.Enrichment_otx_enabled
         Plugin.Enrichment_vulndb_enabled
         Plugin.Enrichment_crowdstrike_falcon_enabled
         Plugin.Enrichment_onyphe_enabled
         Plugin.Enrichment_xforceexchange_enabled
         Plugin.Enrichment_vulners_enabled
         Plugin.Enrichment_macaddress_io_enabled
         Plugin.Enrichment_intel471_enabled
         Plugin.Enrichment_backscatter_io_enabled
         Plugin.Enrichment_hibp_enabled
         Plugin.Enrichment_greynoise_enabled
         Plugin.Enrichment_joesandbox_submit_enabled
         Plugin.Enrichment_virustotal_public_enabled
         Plugin.Enrichment_apiosintds_enabled
         Plugin.Enrichment_urlscan_enabled
         Plugin.Enrichment_securitytrails_enabled
         Plugin.Enrichment_apivoid_enabled
         Plugin.Enrichment_assemblyline_submit_enabled
         Plugin.Enrichment_assemblyline_query_enabled
         Plugin.Enrichment_ransomcoindb_enabled
         Plugin.Enrichment_lastline_query_enabled
         Plugin.Enrichment_sophoslabs_intelix_enabled
         Plugin.Enrichment_cytomic_orion_enabled
         Plugin.Enrichment_censys_enrich_enabled
         Plugin.Enrichment_trustar_enrich_enabled
         Plugin.Enrichment_recordedfuture_enabled
         Plugin.ElasticSearch_logging_enable
         Plugin.S3_enable)
  for PLUG in "${PLUGS[@]}"; do
    ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting ${PLUG} false 2> /dev/null
  done

  # Plugin CustomAuth tuneable
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.CustomAuth_disable_logout" false

  # RPZ Plugin settings
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_policy" "DROP"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_walled_garden" "127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_serial" "\$date00"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_refresh" "2h"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_retry" "30m"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_expiry" "30d"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_minimum_ttl" "1h"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_ttl" "1w"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_ns" "localhost."
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_ns_alt" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.RPZ_email" "root.localhost"

  # Kafka settings
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_brokers" "kafka:9092"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_rdkafka_config" "/etc/rdkafka.ini"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_include_attachments" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_event_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_event_notifications_topic" "misp_event"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_event_publish_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_event_publish_notifications_topic" "misp_event_publish"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_object_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_object_notifications_topic" "misp_object"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_object_reference_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_object_reference_notifications_topic" "misp_object_reference"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_attribute_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_attribute_notifications_topic" "misp_attribute"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_shadow_attribute_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_shadow_attribute_notifications_topic" "misp_shadow_attribute"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_tag_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_tag_notifications_topic" "misp_tag"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_sighting_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_sighting_notifications_topic" "misp_sighting"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_user_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_user_notifications_topic" "misp_user"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_organisation_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_organisation_notifications_topic" "misp_organisation"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_audit_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.Kafka_audit_notifications_topic" "misp_audit"

  # ZeroMQ settings
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_host" "127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_port" 50000
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_host" "localhost"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_port" 6379
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_database" 1
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_redis_namespace" "mispq"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_event_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_object_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_object_reference_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_attribute_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_sighting_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_user_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_organisation_notifications_enable" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_include_attachments" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Plugin.ZeroMQ_tag_notifications_enable" false

  # Force defaults to make MISP Server Settings less RED
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.language" "eng"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.proposals_block_attributes" false

  # Redis block
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.redis_host" "127.0.0.1"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.redis_port" 6379
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.redis_database" 13
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.redis_password" ""

  # Force defaults to make MISP Server Settings less YELLOW
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.ssdeep_correlation_threshold" 40
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.extended_alert_subject" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.default_event_threat_level" 4
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.newUserText" "Dear new MISP user,\\n\\nWe would hereby like to welcome you to the \$org MISP community.\\n\\n Use the credentials below to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nPassword: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.passwordResetText" "Dear MISP user,\\n\\nA password reset has been triggered for your account. Use the below provided temporary password to log into MISP at \$misp, where you will be prompted to manually change your password to something of your own choice.\\n\\nUsername: \$username\\nYour temporary password: \$password\\n\\nIf you have any questions, don't hesitate to contact us at: \$contact.\\n\\nBest regards,\\nYour \$org MISP support team"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.enableEventBlocklisting" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.enableOrgBlocklisting" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.log_client_ip" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.log_auth" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.log_user_ips" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.log_user_ips_authkeys" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disableUserSelfManagement" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disable_user_login_change" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disable_user_password_change" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.disable_user_add" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.block_event_alert" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.block_event_alert_tag" "no-alerts=\"true\""
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.block_old_event_alert" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.block_old_event_alert_age" ""
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.block_old_event_alert_by_date" ""
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.event_alert_republish_ban" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.event_alert_republish_ban_threshold" 5
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.event_alert_republish_ban_refresh_on_retry" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.incoming_tags_disabled_by_default" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.maintenance_message" "Great things are happening! MISP is undergoing maintenance, but will return shortly. You can contact the administration at \$email."
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.footermidleft" "This is an initial install"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.footermidright" "Please configure and harden accordingly"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.welcome_text_top" "Initial Install, please configure"
  # TODO: Make sure $FLAVOUR is correct
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.welcome_text_bottom" "Welcome to MISP on ${FLAVOUR}, change this message in MISP Settings"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.attachments_dir" "${PATH_TO_MISP}/app/files"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.download_attachments_on_load" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.event_alert_metadata_only" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.title_text" "MISP"
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.terms_download" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.showorgalternate" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "MISP.event_view_filter_fields" "id, uuid, value, comment, type, category, Tag.name"

  # Force defaults to make MISP Server Settings less GREEN
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "debug" 0
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.auth_enforced" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.log_each_individual_auth_fail" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.rest_client_baseurl" ""
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.advanced_authkeys" false
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.password_policy_length" 12
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.password_policy_complexity" '/^((?=.*\d)|(?=.*\W+))(?![\n])(?=.*[A-Z])(?=.*[a-z]).*$|.{16,}/'
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.self_registration_message" "If you would like to send us a registration request, please fill out the form below. Make sure you fill out as much information as possible in order to ease the task of the administrators."

  # Appease the security audit, #hardening
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.disable_browser_cache" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.check_sec_fetch_site_header" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.csp_enforce" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.advanced_authkeys" true
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.do_not_log_authkeys" true

  # Appease the security audit, #loggin
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin setSetting "Security.username_in_response_header" true

  # It is possible to updateMISP too, only here for reference how to to that on the CLI.
  ## ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateMISP

  # Set MISP Live
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Live ${MISP_LIVE}
}

updateGOWNT () {
  # AUTH_KEY Place holder in case we need to **curl** somehing in the future
  # 
  ${SUDO_WWW} ${RUN_MYSQL} -- mysql -h ${DBHOST} -u ${DBUSER_MISP} -p${DBPASSWORD_MISP} misp -e "SELECT authkey FROM users;" | tail -1 > /tmp/auth.key
  AUTH_KEY=$(cat /tmp/auth.key)
  rm /tmp/auth.key

  debug "Updating Galaxies, ObjectTemplates, Warninglists, Noticelists and Templates"
  # Update the galaxies…
  # TODO: Fix updateGalaxies
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateGalaxies
  # Updating the taxonomies…
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateTaxonomies
  # Updating the warning lists…
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateWarningLists
  # Updating the notice lists…
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateNoticeLists
  # Updating the object templates…
  ${SUDO_WWW} ${RUN_PHP} -- ${CAKE} Admin updateObjectTemplates "1337"
}


prepareUser
enableEPEL
debug "Installing System Dependencies"
yumInstallCoreDeps7
installEntropyRHEL
debug "Installing MISP code"
installCoreRHEL7
debug "Install Cake PHP"
installCake_RHEL
debug "Setting File permissions"
permissions_RHEL7
debug "Preparing Database"
prepareDB_RHEL
apacheConfig_RHEL7


debug "Enabling Haveged for additional entropy"
sudo yum install haveged -y
sudo systemctl enable --now haveged.service


debug "Setting up firewall"
firewall_RHEL

debug "Enabling log rotation"
logRotation_RHEL

debug "Configuring MISP"
configMISP_RHEL

debug "Setting up background workers"
configWorkersRHEL

debug "Optimizing Cake Installation"
coreCAKE

debug "Updating tables"
updateGOWNT

echo "Core Intallation finished, check on port 443 to see the Web UI"

sudo systemctl restart php-fpm.service
