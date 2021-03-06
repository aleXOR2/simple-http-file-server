Information
===========

This is a simple python HTTP server which supports uploads. Doing GET path/to/file
will return the content of path relative to the current directory the server
was started from. Doing PUT path/to/file will upload a file to the path relative
to the current directory. Any existing directories are automatically created.
PUT fails if the given path identifies an existing directory or creating needed
directories would overwrite an existing file.

Usage
=====

Just start the server by command line:

    python3 server.py

The server implements a simple permission system. Users authenticate via HTTP
Basic authentication. The permissions are stored in a python file (see below):

    python3 server.py --access_config ../perms.json

Permissions
===========

The permissions and user authentication information are specified via a json
file. The server expects to be supplied with user and password via HTTP Basic
authentication. If HTTP request specifies user and the user is not found in the
database or the password does not match, the request always fail. If no
authentication information is supplied then the server assumes user "*" as far
as permissions are concerned.

Two permissions are supported: "read" and "write". Whether a read (GET request)
or a write (PUT request) is supported depends on what permissions are specified
for the path in question and its parent paths.

The permissions are determined as follows:
 - if the current path has permissions for the current user, then:
    - "r" and "rw" allows read operation
    - "w" and "rw" allows write operation
    - "" allows neither
 - otherwise, if the current path has permissions for the user "*", then
    - "r" and "rw" allows read operation
    - "w" and "rw" allows write operation
    - "" allows neither
 - otherwise, the permissions set for the parent path determines whether the
   operation is allowed.

Note in particular, that permissions set for a different user, except "*", are
ignored.

An example permission file:

    {
        "paths" : [
            { "path" : ".", "user" : "*", "perms" : "r" },
            { "path" : "test", "user" : "testuser", "perms" : "w" }
        ],
        "users" : [
            { "user" : "testuser", "psw" : "testpass" }
        ]
    }

License
=======

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
