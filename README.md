This is essentially an experiment/prototype that got a little too big and had some potential. So it's being turned into a project.

proto.py is the original prototype.

protodeploy is the original exerimental deploy script that worked for at least two of the django apps I work on.

This project uses inquirer to get user input. As far as I know it only works on linux and mac. 
When debugging in pycharm, you may need to set the run/debug settings to use the terminal emulation.
You can find a link with more info here: https://intellij-support.jetbrains.com/hc/en-us/community/posts/360003383619-Pycharm-2019-termios-error-25-Inappropriate-ioctl-for-device-?page=1#community_comment_6589796593042 and here https://github.com/magmax/python-readchar/issues/11


```shell
poetry run protodeploy
```

```shell
poetry run start
```

```shell
poetry run protocheckdb
```

```shell
poetry run protogetkeys
```

```shell
poetry run protogetdbcluster
```

```shell
poetry run protoselectcluster
```

```shell
poetry run protoselect_spaces
```


https://cloud.digitalocean.com/apps/github/install