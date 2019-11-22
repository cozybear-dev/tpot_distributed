#!/usr/bin/env python

#This toolkit works with TPOT 17.10 and 18.11 *!*till 3 december 2018*!*
#Adbhoney is not yet added since it was added to TPOT after the final toolkit save - this can be easily done by modifying the logstash.conf and filebeat.yml, check the research paper for more information on adding a honeypot.

"""
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""


"""
To do:

- Add functions to configure reverse proxies
- Add additional logging to logging server (add local logstash input and apply the configure_additional_logging method - quick win)
- Add logrotate changes to prevent full disk on loggingserver (and honeypots - standard is 30 days)
- Add IP table rules for loggingserver [IMPORTANT - all open ports on the logging server will be publicly accessible and attackable, change for production use.]
- SSL Common Name verification is not enabled on filebeat, it is on elasticsearch and logstash. It is recommended to change this by changing the CN (0.0.0.0) accordingly in the create_certificates.sh script. This enforces Filebeat authentication the logstash instance using SSL.

- If elasticsearch fails => sysctl -w vm.max_map_count=262144

(FYI; syntax using Fabric is "fab [METHOD]:{parameter},{parameter},etc", must be run inside the folder containg the fabfile)

You can check all the methods with the command: "fab help"


"""
from fabric.api import local, env, run, put, sudo, roles, warn_only, hide, get
import time

#TPOT SSH port is 64295 NOT 22, that's a honeypot lol
env.hosts = ['derp@192.168.253.133:22, tsec@192.168.253.136:64295'] #Yes the double entries are requried
env.roledefs={"honeypots":["tsec@192.168.253.136:64295"],"loggingserver":["derp@192.168.253.133:22"], "reverse_proxies":[""]}
env.passwords = {'derp@192.168.253.133:22': 'admin', 'tsec@192.168.253.136:64295': 'admin'} #I know how this looks but there is no better workaround than this as far as I know

@roles('honeypots')
def initialize_honeypot(logging, filebeat_config, tpot_config, tpot_service, filebeat_crt, filebeat_key, root_crt, path, cockpit_ssh):
    """ Initialize all the honeypots to finish TPOT 1710/1811 installation"""
    install_filebeat(filebeat_config, tpot_config, tpot_service, filebeat_crt, filebeat_key, root_crt)
    configure_cockpit(cockpit_ssh)
    configure_additional_logging(logging)
    add_sshkey(path)
    sudo('service tpot restart')
    print('Done with initialize_honeypot')

def ssh_hardening():
    """WARNING: ONLY execute when the public keys are inside the all the authorized_keys files"""
    #Simple hardening but effective for most threats
    sudo('echo "PasswordAuthentication no" >> /etc/ssh/sshd_config')
    sudo('service sshd restart')

def add_sshkey(path):
    """Add sshkey to enable passwordless root access"""
    sudo('mkdir -p /root/.ssh/') #Not dynamic on purpose to force root instead of depending on system variables
    put(path, '/tmp/id_rsa_logging.pub', use_sudo=True)
    sudo('cat /tmp/id_rsa_logging.pub >> /root/.ssh/authorized_keys')
    sudo('rm /tmp/id_rsa_logging.pub')
    print('Done with add_sshkey')

@roles('honeypots')
def update_tpotconfig(tpotconfig):
    """Update TPOT config"""
    put(tpotconfig, '/opt/tsec/etc/tpot.yml', use_sudo=True)
    print('Done with upload_tpotconfig')

@roles('honeypots')
def update_tpotservice(tpotservice):
    """Update TPOT service"""
    put(tpotservice, '/etc/systemd/system/tpot.service', use_sudo=True)
    print('Done with upload_tpotservice')

@roles('loggingserver')
def restart_loggingserver():
    """Restart the server"""
    print('IMPORTANT: Error code nonzero reurn code -1 is normal')
    sudo('shutdown -r now')

@roles('loggingserver')
def get_config(config):
    """Get config of choise from loggingserver; elastic | kibana | logstash"""
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    if config == 'elastic':
        sudo('docker cp %s:/etc/elasticsearch/elasticsearch.yml /tmp/elasticsearch.yml' % str(id))
        get('/tmp/elasticsearch.yml', '$pwd/elasticsearch.yml')
    if config == 'kibana':
        sudo('docker cp %s:/opt/kibana/config/kibana.yml /tmp/kibana.yml' % str(id))
        get('/tmp/kibana.yml', '$pwd/elasticsearch.yml')
    if config == 'logstash':
        sudo('docker cp %s:/etc/logstash/conf.d/logstash.conf /tmp/logstash.conf' % str(id))
        get('/tmp/logstash.conf', '$pwd/logstash.conf')
    else:
        print('Unknown config - ERROR')

@roles('loggingserver')
def update_start(start):
    """Update the start.sh script of the ELK container"""
    put(start, '/tmp/start.sh')
    sudo('chmod 777 /tmp/start.sh')
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    sudo('docker cp /tmp/start.sh %s:/usr/local/bin/start.sh' % str(id))
    sudo('docker commit %s sebp/elk:custom' % str(id)) #it does not matter if the version is the same, it will be overwritten.
    sudo('docker stop %s' % str(id))
    sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')
    print('Done with start.sh, server restarting now')

@roles('loggingserver')
def update_elasticconfig(elasticconfig):
    """Update Elasticsearch config"""
    put(elasticconfig, '/tmp/elasticsearch.yml')
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    sudo('docker cp /tmp/elasticsearch.yml %s:/etc/elasticsearch/elasticsearch.yml' % str(id))
    sudo('docker commit %s sebp/elk:custom' % str(id)) #it does not matter if the version is the same, it will be overwritten.
    sudo('docker stop %s' % str(id))
    sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')

    print('Done with update_elasticconfig, server restarting now')

@roles('loggingserver')
def update_kibanaconfig(kibanaconfig):
    """Update Kibana config"""
    put(kibanaconfig, '/tmp/kibana.yml')
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    sudo('docker cp /tmp/kibana.yml %s:/opt/kibana/config/kibana.yml' % str(id))
    sudo('docker commit %s sebp/elk:custom' % str(id)) #it does not matter if the version is the same, it will be overwritten.()
    sudo('docker stop %s' % str(id))
    sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')

    print('Done with update_kibanaconfig, server restarting now')

@roles('loggingserver')
def update_logstashconfig(logstashconfig):
    """Update Logstash config"""
    put(logstashconfig, '/tmp/logstash.conf')
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    sudo('docker exec %s sh -c "rm /etc/logstash/conf.d/*.conf"' % str(id)) #Remove all the various config files that will conflict with the updated one - this is logstash only
    sudo('docker cp /tmp/logstash.conf %s:/etc/logstash/conf.d/logstash.conf' % str(id))
    sudo('docker commit %s sebp/elk:custom' % str(id)) #it does not matter if the version is the same, it will be overwritten.
    sudo('docker stop %s' % str(id))
    sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')
    print('Done with upload_logstashconfig, server restarting now')

@roles('loggingserver')
def update_kibanainit(kibanainit):
    """Update Kibana initialization file"""
    put(kibanainit, '/tmp/kibana')
    sudo('chmod 777 /tmp/kibana')
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    sudo('docker cp /tmp/kibana %s:/etc/init.d/kibana' % str(id))
    sudo('docker commit %s sebp/elk:custom' % str(id)) #it does not matter if the version is the same, it will be overwritten.
    sudo('docker stop %s' % str(id))
    sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')
    print('Done with upload_logstashconfig, server restarting now')


@roles('loggingserver')
def save_elk():
    """Save current state ELK container""" #I know I could (should) use this in all the update methods but didn't
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    sudo('docker commit %s sebp/elk:custom' % str(id))
    sudo('docker stop %s' % str(id))
    sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')
    print('Done with save_elk, server restarting now')

@roles('loggingserver')
def install_listbot():
    """Install listbot for logstash"""
    sudo('apt -y install curl prips')
    sudo('wget -O /tmp/gen_iprep_map.sh https://raw.githubusercontent.com/dtag-dev-sec/listbot/master/src/gen_iprep_map.sh')
    sudo('wget -O /tmp/gen_cve_map.sh https://raw.githubusercontent.com/dtag-dev-sec/listbot/master/src/gen_cve_map.sh')
    sudo('chmod 777 /tmp/gen_cve_map.sh /tmp/gen_iprep_map.sh')
    sudo('cd /tmp; /tmp/gen_cve_map.sh')
    sudo('cd /tmp; /tmp/gen_iprep_map.sh')
    time.sleep(10) #wait for reboot to finish
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    with warn_only():
        sudo('docker exec %s mkdir /etc/listbot' % str(id))
    sudo('docker cp /tmp/cve.yaml %s:/etc/listbot/cve.yaml' % str(id))
    sudo('docker cp /tmp/iprep.yaml %s:/etc/listbot/iprep.yaml' % str(id))
    sudo('docker cp /tmp/gen_cve_map.sh %s:/etc/listbot/gen_cve_map.sh' % str(id))
    sudo('docker cp /tmp/gen_iprep_map.sh %s:/etc/listbot/gen_iprep_map.sh' % str(id))
    test = "\"0 0 * * * /etc/listbot/gen_cve_map.sh\"" #Two different types of quotes were not enough and escaping did not work inside the sudo command, therefore this bypass.
    test2 = "docker exec %s bash -c 'echo %s >> /tmp/crony'" % (str(id), str(test))
    sudo('%s' % str(test2))
    test="\"0 0 * * * /etc/listbot/gen_iprep_map.sh\""
    sudo('%s' % str(test2))
    sudo('docker exec %s crontab /tmp/crony' % str(id))
    sudo('docker commit %s sebp/elk:custom' % str(id)) #it does not matter if the version is the same, it will be overwritten.
    sudo('docker stop %s' % str(id))
    sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')
    print('Done with intall_listbot, server restarting now')

@roles('loggingserver')
def initialize_loggingserver(update_sh, kibana, logstashconfig, kibanaconfig, elasticconfig, elkscript_start, elkscript_stop, elkservice, cockpit_crt, cockpit_key, elastic_crt, elastic_key, logstash_crt, logstash_key, kibana_crt, kibana_key, root_crt, start):
    """Initialize the loggingserver"""
    add_sshkey('/root/.ssh/id_rsa.pub')
    install_elk(update_sh)
    start_command_elk('563789246')
    install_elk_service(elkscript_start, elkscript_stop, elkservice)
    install_elastalert()
    install_searchguard()
    install_cockpit()
    install_certificates(cockpit_crt, cockpit_key, elastic_crt, elastic_key, logstash_crt, logstash_key, kibana_crt, kibana_key, root_crt)
    install_listbot()
    update_logstashconfig(logstashconfig) #add grok filter for additional commands, ssl cert config for elasticsearch and ssl cert config for filebeat
    update_kibanaconfig(kibanaconfig) #set ssl config right, add elastalert snippet (see method), add elasticsearch username and password, disable ssl veri mode, disable xpack.
    update_elasticconfig(elasticconfig) #add searchguard snippet
    update_kibanainit(kibana)
    update_start(start)
    sudo('sysctl -w vm.max_map_count=262144') #The standard vm.max_map_count is too low for elasticsearch causing it to fail
    sudo('shutdown -r now') #pray it works
    print('Done with initialize_loggingserver')

@roles('loggingserver')
def install_certificates(cockpit_crt, cockpit_key, elastic_crt, elastic_key, logstash_crt, logstash_key, kibana_crt, kibana_key, root_crt):
    """Install all the TLS certificates created with create_certificates.sh"""
    put(cockpit_crt, '/tmp/cockpit.crt', use_sudo=True)
    put(cockpit_key, '/tmp/cockpit.key', use_sudo=True)
    put(elastic_crt, '/tmp/elastic.crt', use_sudo=True)
    put(elastic_key, '/tmp/elastic.key', use_sudo=True)
    put(logstash_crt, '/tmp/logstash.crt', use_sudo=True)
    put(logstash_key, '/tmp/logstash.key', use_sudo=True)
    put(kibana_crt, '/tmp/kibana.crt', use_sudo=True)
    put(kibana_key, '/tmp/kibana.key', use_sudo=True)
    put(root_crt, '/tmp/rootCA.crt', use_sudo=True)
    sudo('cd /tmp; cat cockpit.crt >> cockpit.cert')
    sudo('cd /tmp; cat cockpit.key >> cockpit.cert')
    sudo('mv /tmp/cockpit.cert /etc/cockpit/ws-certs.d/cockpit.cert')
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    sudo('docker cp /tmp/elastic.crt %s:/etc/elasticsearch/elastic.crt' % str(id))
    sudo('docker cp /tmp/elastic.key %s:/etc/elasticsearch/elastic.key' % str(id))
    sudo('docker cp /tmp/rootCA.crt %s:/etc/elasticsearch/rootCA.crt' % str(id))
    sudo('docker cp /tmp/logstash.crt %s:/etc/logstash/logstash.crt' % str(id))
    sudo('docker cp /tmp/logstash.key %s:/etc/logstash/logstash.key' % str(id))
    sudo('docker cp /tmp/rootCA.crt %s:/etc/logstash/rootCA.crt' % str(id))
    sudo('docker cp /tmp/kibana.crt %s:/opt/kibana/config/kibana.crt' % str(id))
    sudo('docker cp /tmp/kibana.key %s:/opt/kibana/config/kibana.key' % str(id))
    sudo('docker commit %s sebp/elk:custom' % str(id))
    sudo('docker stop %s' % str(id))
    sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')


@roles('loggingserver')
def install_elk(update_sh):
    """Install Docker and get ELK image"""
    sudo('apt update')
    sudo('apt -y install docker.io')
    sudo('docker pull sebp/elk:642')
    put(update_sh, '/opt/tpot/bin/updateip.sh', use_sudo=True)
    sudo('mkdir -p /data/suricata/log/') #Logstash does not have permissions to create this file in this map that does not exist yet
    sudo('touch /data/suricata/log/suricata_ews.log')
    sudo('chmod 666 /data/suricata/log/suricata_ews.log')


@roles('loggingserver')
def start_command_elk(unique_boot_code):
    """Create custom ELK container - only used in installation - use restart_elkservice instead"""
    #Added unique_boot_code to prevent accidental wrong use since only the installation method should access this method.
    print('WARNING: this method is only used in the installation and will not work after the installation => use restart_elkservice')
    print(unique_boot_code)
    if unique_boot_code == '563789246':
        sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --restart unless-stopped -it sebp/elk:642')
        id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
        sudo('docker commit %s sebp/elk:custom' % str(id))
        sudo('docker stop $(docker ps -aq)') #the restart of the service does not stop the current containers since the service has not been activated yet, therefore this manual commando
        sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')
        with warn_only():
            sudo('docker rmi --force $(docker images | grep "<none>" | tr -s " " | cut -d " " -f 3)')
    else:
        print('Wrong boot code - start_command_elk failed')
        exit()

@roles('loggingserver')
def restart_elkservice():
    """Restart the ELK service"""
    sudo('service elk restart')

@roles('loggingserver')
def install_elk_service(elkscript_start, elkscript_stop, elkservice):
    """Install the ELK service"""
    put(elkscript_start, '/usr/bin/start_elkdocker.sh', use_sudo=True)
    put(elkscript_stop, '/usr/bin/stop_elkdocker.sh', use_sudo=True)
    sudo('chmod 755 /usr/bin/start_elkdocker.sh /usr/bin/stop_elkdocker.sh')
    put(elkservice, '/etc/systemd/system/elk.service', use_sudo=True)
    sudo('systemctl daemon-reload')
    sudo('systemctl enable elk')

@roles('loggingserver')
def install_searchguard():
    """Install SearchGuard for Kibana and Elasticsearch"""
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    sudo('wget https://search.maven.org/remotecontent?filepath=com/floragunn/search-guard-kibana-plugin/6.4.2-15/search-guard-kibana-plugin-6.4.2-15.zip -O /tmp/kibana.zip')
    sudo('docker cp /tmp/kibana.zip %s:/tmp/kibana.zip' % str(id))
    with warn_only(): #Warn only is on purpose, although the installation is successful Fabric will read it as an error and otherwise abort
        sudo('docker exec -it %s /opt/kibana/bin/kibana-plugin install file:///tmp/kibana.zip' % str(id))
        time.sleep(10)
        sudo('docker exec -it %s /opt/elasticsearch/bin/elasticsearch-plugin install -b com.floragunn:search-guard-6:6.4.2-23.1' % str(id))
    sudo('docker commit %s sebp/elk:custom' % str(id))
    sudo('docker stop %s' % str(id))
    sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')
    print('Done installing searchguard - YOU NEED TO CONFIGURE THE ACCOUNTS MANUALLY, ADMIN:ADMIN')

@roles('loggingserver')
def install_elastalert():
    """Install Elastalert for Kibana and Elasticsearch as well as the Docker container"""
    sudo('wget https://github.com/bitsensor/elastalert-kibana-plugin/releases/download/1.0.1/elastalert-kibana-plugin-1.0.1-6.4.2.zip -O /tmp/elastalert.zip')
    id = sudo("docker ps | awk '{ print $1,$2 }' | grep elk | awk '{print $1 }'")
    sudo('docker cp /tmp/elastalert.zip %s:/tmp/elastalert.zip' % str(id))
    print('The installation will take a while... DO NOT INTERRUPT')
    with warn_only():
        sudo('docker exec -it %s /opt/kibana/bin/kibana-plugin install file:///tmp/elastalert.zip' % str(id)) #YES THREE FORWARD SLASHES
    sudo('docker commit %s sebp/elk:custom' % str(id))
    sudo('cd /etc; git clone https://github.com/bitsensor/elastalert.git; cd elastalert')
    sudo('docker run -d -p 3030:3030 --restart unless-stopped \
    -v /etc/elastalert/config/elastalert.yaml:/opt/elastalert/config.yaml \
    -v /etc/elastalert/config/config.json:/opt/elastalert-server/config/config.json \
    -v /etc/elastalert/rules:/opt/elastalert/rules \
    -v /etc/elastalert/rule_templates:/opt/elastalert/rule_templates \
    --net=host \
    bitsensor/elastalert:latest')
    sudo('docker stop %s' % str(id))
    sudo('docker run -d -p 5601:5601 -p 9200:9200 -p 5044:5044 --net=host --restart unless-stopped -it sebp/elk:custom')
    print('Done with install_elastalert')

@roles('loggingserver')
def start_cockpit():
    """Start Cockpit webservice"""
    sudo('service cockpit start')

@roles('loggingserver')
def install_cockpit():
    """Install Cockpit""" #By far the best tool out there in terms of monitoring imho
    sudo('apt -y install cockpit cockpit-docker')
    get('/root/.ssh/id_rsa.pub', '/tmp/id_rsa_cockpit.pub', use_sudo=True)
    print('Done with install_cockpit')

@roles('honeypots')
def configure_cockpit(path):
    """Configure cockpit by adding loggingserver public SSH key"""
    sudo('mkdir -p /root/.ssh')
    put(path, '/root/.ssh/id_rsa_cockpit.pub', use_sudo=True)
    sudo('cat /root/.ssh/id_rsa_cockpit.pub >> /root/.ssh/authorized_keys')
    print('SSH will restart, expect a crash of the script')
    with warn_only():
        sudo('service sshd restart')
    print('configure cockpit done')

@roles('reverse_proxies')
def initialize_reverse_proxies(docker_id, tcpd_start, tcpd_stop, tcpdservice):
    """WORK IN PROGRESS - DO NOT USE, method to initialize the reverse proxies"""
    sudo('docker pull corfr/tcpdump:latest')
    install_tcpd_service(tcpd_start, tcpd_stop, tcpdservice)
    reverse_proxy_service('restart')
    #what if reverse proxy is down?
    #how to dynamic reverse proxy configuration

@roles('reverse_proxies')
def install_tcpd_service(tcpd_start, tcpd_stop, tcpdservice):
    """WORK IN PROGRESS - DO NOT USE, method to install tcpdump service"""
    put(tcpd_start, '/usr/bin/start_tcpd.sh', use_sudo=True)
    put(tcpd_stop, '/usr/bin/stop_tcpd.sh', use_sudo=True)
    put(tcpdservice, '/etc/systemd/system/tcpd.service', use_sudo=True)
    sudo('systemctl daemon-reload')
    sudo('systemctl enable elk')

@roles('reverse_proxies')
def reverse_proxy_service(command):
    """WORK IN PROGRESS - DO NOT USE, method to control the reverse proxy service"""
    if command == 'start':
        sudo('')
    elif command == 'stop':
        sudo('')
    elif command == 'restart':
        sudo('')
    else:
        print('Command not supported. Exiting.')

def get_ip():
    """Get the public IP of all servers"""
    with hide('everything'):
        sudo('apt-get -y install curl')
        IP = sudo('curl https://ipinfo.io/ip')
    item = env.host_string
    print('The current host as defined in this script: ' + env.host_string)
    for key in env.roledefs.keys():
        if item in env.roledefs[key]:
            print('Role: ' + key)
    print('Current public IP: ' + IP)

@roles('honeypots')
def restart_tpot_service():
    """Restart the TPOT service on all honeypots"""
    sudo('service tpot restart')
    print('This will take a few minutes to succeed, so have patience. Check current status via "status_honeypot".')

@roles('honeypots')
def status_honeypot():
    """Check the container status on all honeypots"""
    sudo('dps.sh')
    print('Done with status_honeypot')

@roles('honeypots')
def update_filebeatconfig(filebeat_config):
    """Update Filebeat config"""
    put(filebeat_config, '/etc/filebeat/filebeat.yml', use_sudo=True)
    sudo('chown root:root /etc/filebeat/filebeat.yml')
    sudo('chmod go-w /etc/filebeat/filebeat.yml')
    sudo('service tpot restart')

@roles('honeypots')
def install_filebeat(filebeat_config, tpot_config, tpot_service, filebeat_crt, filebeat_key, root_crt):
    """Install filebeat on the honeypots"""
    print('INFO: the current version that will be installed is ELK 6.4.2, feel free to change the version upwards but know that the chance the setup will break is high.')
    run('wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-6.4.2-amd64.deb')
    sudo('dpkg -i filebeat*.deb')
    put(filebeat_config, '/etc/filebeat/filebeat.yml', use_sudo=True)
    put(filebeat_crt, '/etc/filebeat/filebeat.crt', use_sudo=True)
    put(filebeat_key, '/etc/filebeat/filebeat.key', use_sudo=True)
    put(root_crt, '/etc/filebeat/rootCA.crt', use_sudo=True)
    put(tpot_service, '/etc/systemd/system/tpot.service', use_sudo=True) #Add filebeat to service
    put(tpot_config, '/opt/tpot/etc/tpot.yml', use_sudo=True)
    sudo('chmod 644 /etc/systemd/system/tpot.service')
    print('Filebeat installed & configured. TPOT has been restarted, this will take a few minutes to succeed. Check current status via "status_honeypot".')

@roles('honeypots')
def configure_additional_logging(logging):
    """Configure additional logging that logs all the commands of all users""" #This is more stealthy and reliable than using e.g. auditd
    put(logging, '/tmp/logging.sh', use_sudo=True)
    sudo('chmod 755 /tmp/logging.sh')
    sudo('./tmp/logging.sh')
    print('Done with configure_additional_logging')

@roles('honeypots')
def restart_honeypot():
    """Restart all honeypot servers"""
    sudo('shutdown -r now')
