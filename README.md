# TryHackMe Room - Hamlet

![Banner](https://github.com/IngoKl/THM-Hamlet/blob/main/room_design/banner.png)

This room has been released on [*TryHackMe* as *Hamlet*](https://tryhackme.com/room/hamlet) on January 14th, 2022. So far, the challenge has been well received! 🤗

## Overview

This is a Shakespeare/Hamlet-inspired [TryHackMe](https://tryhackme.com/room/hamlet) room in which you will explore an uncommon web application used in linguistic/NLP research. More precisely, you will use a misconfigured webserver to get a foothold within a `Docker` container. After escalating your privileges, you will escape from the container and gain root on the machine. Of course, there are one or two rabbit holes, possibilities for alternative attack paths as well as some fun references to Hamlet.

There's an ['official' walkthrough](https://github.com/IngoKl/THM-Hamlet/blob/main/solution/official-walkthrough.md) available that runs you through the room. Before looking at this walkthrough or the following hints towards building your own machine, try to go through the machine on your own!

**Note:** This repository, in order to somewhat protect the integrity of the challenge, does not contain the credentials and flags used for the actual *TryHackMe* room.
This is also why this repository does not feature a commit history.
However, this should not stop you from setting up your own lab environment. Replace *REDACTED* with credentials and flags of your choice!

## Learning Objectives

Hacking your way through this room, you will learn how to ...

- navigate and exploit specialized and uncommon software (`WebAnno`).
- creatively leverage the intended capabilities of an application in an attack.
- create custom wordlists from websites.
- leverage PHP web shells.
- do some basic Linux privilege escalation.
- escape from a `Docker` container that runs `--privileged`.
- work with `yescrypt` hashes.
- work in an environment with `ufw` enabled in conjunction with `Docker`.
- combine different services/angles within one attack.

## Creating Your Own VM

Most of the heavy lifting is done by `Vagrant`. Nevertheless, a few changes need to be made after creating the machine. In particular, `WebAnno` is best populated manually as copying the HSQLDB leads to many issues. This could be mitigated by using a MySQL database. However, this increases the complexity quite a bit and introduces further possible (unintended) attack vectors.

If you want to build your own VM, do the following:

- Run `vagrant up` to start/build the base system. (use `vagrant halt` to shut the system down)
- Manually populate `WebAnno`
  - Create the *Hamlet* project with a custom annotation layer *OpheliasNotes*.
  - Create both the *ophelia* as well as the *ghost* (ghost:REDACTED) user. *ghost* needs admin rights to add files to the project. The password for *ophelia* does not matter but it should be strong.
  - Add *Hamlet* to the project.
  - *ophelia* and *ghost* need access to the Hamlet project.
  - Add the credential note to *Hamlet* using the *ophelia* user and the `OpheliasNotes` layer. (Note: Don't forget that the REDACTED password does not work for WebAnno.)
  - Change the *admin* password.
- Check if the containers are running and whether the passwords/bits have been set correctly.

Of course, the same can be achieved using, for example, `VMWare Workstation`. In this case, you can simply reproduce the steps in `bootstrap.sh` within the VM. The instance running on THM right now, for example, has been edited using `Workstation` before submission.

### Docker Containers

Two containers should be running `web` and `webanno`.

- To list the containers, run: `sudo docker container ls`
- To interact (shell) with a container, run: `sudo docker exec -it web bash`

### Default Credentials on a Fresh VM

The default credentials need to be set up in the `bootstrap.sh` file as well as in the `/data` folder.

### Known Bugs/Issues

This are known bugs or issues with *THM-Hamlet*. The versions refer to the images uploaded to *TryHackMe*.

#### Hamlet-1.1 (Release on THM)

- The edition used for the gravediggers service (`501`) does not match the edition in `hamlet.txt`. While different editions are hinted towards on the website, this might confuse learners who are focusing on the provided edition. (*Thank you [CyberVikingUK](https://www.twitch.tv/cybervikinguk/video/1271595652) for pointing this issue out*)
