# Ubuntu Server для x-ui-pro

Скрипт настраивает вход по SSH-ключу, UFW и Fail2ban на Ubuntu Server с systemd. SSH-порт берётся из текущего подключения. Для x-ui-pro добавляются правила на 80/tcp, 443/tcp и 443/udp. Если у провайдера есть отдельный firewall, открой те же входящие порты в его панели.

## Запуск

Добавь свой публичный SSH-ключ на VPS. Скачай скрипт из этого репозитория и скопируй его на сервер через `scp`. Для прямого клонирования с VPS можно добавить [deploy key только на чтение](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys) и указать соответствующий ключ:

```bash
GIT_SSH_COMMAND='ssh -i ~/.ssh/ubuntu-xui-security-deploy -o IdentitiesOnly=yes' \
  git clone git@github.com:Skulift/ubuntu-xui-security.git
cd ubuntu-xui-security
```

Из действующей SSH-сессии запусти:

```bash
sudo --preserve-env=SSH_CONNECTION bash ./ubuntu-xui-security.sh apply
```

Оставь первую сессию открытой. Подключись к VPS с ключом из второго окна и выполни напечатанную скриптом команду подтверждения. Если подтверждения нет пять минут, скрипт откатывает настройки SSH. Дождись подтверждения или отката перед перезагрузкой.

Для входа **только по сертификатам OpenSSH** передай `apply --ca-pub /путь/к/ca.pub` и используй во второй сессии сертификат, подписанный этим CA для твоего SSH-пользователя. Для другого UDP-порта Hysteria 2 добавь `--hy2-port ПОРТ` в оба установщика.

## Установка x-ui-pro

При запуске установщика x-ui-pro добавь `--skip-ufw`. Скрипт безопасности уже настроил правила UFW, включая порт текущего SSH-подключения.

Синтаксис Bash, подтверждение из второй сессии и откат проверены локально с заглушками. Прогон на живом Ubuntu VPS ещё предстоит.
