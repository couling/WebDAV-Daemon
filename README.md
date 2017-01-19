# webdavd(1) - WebDAV daemon

# About

webdavd is a WebDAV server designed to be a replace for SMBA providing access to a system's files without taking ownership of them.  It aims to differ from most WebDAV servers on a number of points:

 - Users are authenticated through PAM and are *always* operating system users.
 - The webserver switches OS user to match the authenticated user before accessing any files.
 - The daemon operates without any prior knowledge of the files it's serving.  
 - The daemon does NOT take ownership of the files it modifies and serves. It does not take ownership of any files in any way.  Even locking operations are implemented using the native OS `flock()` function.

#  Starting the server

If properly installed the server can be started with:

	service webdavd start

The server can be started manually by calling:

    webdavd config-file [config-file ...]
    
See [Configuration](Configuration.md) for details of the config file.

# Known Issues

 - Locking file is limited and it is currently not possible to lock a directory
 - PAM sessions are of a fixed length and their length is not affected by user activity.
