#!/bin/bash
echo "PROMPT_COMMAND='history -a >(tee -a ~/.bash_history | logger -t \"\$USER[\$\$] \$SSH_CONNECTION INFO Command executed\")'" >> /etc/bash.bashrc
echo "export >/dev/null" >> /etc/bash.bashrc
