#!/usr/local/bin/python3
# Author: Diljot Garcha
# Date completed: August 1, 2019
# Remarks: A basic Python Web Server
# Flair: Web Server

# Import statements
import os
import socket
import select
import platform
import mimetypes
import subprocess
from threading import Thread

# Constants
HOST = ""
PORT = 80

# HTTP related constants
GET = "GET"
POST = "POST"
HTTP_VERSION = "HTTP/1.0"

# Response codes
OK = "OK"
OK_CODE = 200
NOT_FOUND = "Not Found"
NOT_FOUND_CODE = 404
ERROR = "Internal Server Error"
ERROR_CODE = 500
REDIRECT = "Moved Permanently"
REDIRECT_CODE = 301

# File related constants
SCRIPT = ".cgi"
CSS = ".css"
DEFAULT_PAGE = "index.html"
HTML_CONTENT = "text/html"
DEFAULT_TITLE = "Web Server Flair"
READ_BIN = "rb"
READ_WRITE_BIN = "rwb"

# Environment constants
QUERY_STRING_ENV = "QUERY_STRING"
HTTP_COOKIE_ENV = "HTTP_COOKIE"
REQUEST_METHOD_ENV = "REQUEST_METHOD"
CONTENT_LENGTH_ENV = "CONTENT_LENGTH"

# Header Constants
CONTENT_TYPE_HEADER = "Content-Type:"
CONTENT_LENGTH_HEADER = "Content-Length:"
COOKIE_HEADER = "Cookie:"
LOCATION_HEADER = "Location:"

# Log constants
SERVER_LOG = "[Server Log]"
SERVER_ERROR = "[Server Error]"

# Other constants
FIRST_ELEMENT = 0
SECOND_ELEMENT = 1
NEW_LINE = "\n"
END_OF_STREAM = "\r\n"
UTF = "utf-8"
QUESTION = "?"
ASCII_SPACE = "%20"
WINDOWS = "Windows"
TIMEOUT = 2

"""
---------------------------------------------------------------------
---------------------------------------------------------------------
                        Web Server Class
---------------------------------------------------------------------
---------------------------------------------------------------------
"""


# Stream server
class WebServer:
    """
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
                Embedded inner class for handling our page header
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    """

    class Header:
        # Constructor
        def __init__(self):
            # Privates
            self.__header = []

        # Start the header
        def set_content_type(self, content_type):
            self.__header.append("{} {}".format(CONTENT_TYPE_HEADER, content_type))

        # Adds the HTTP code to the header
        def set_http_code(self, code):
            if code == OK:
                self.__header.append("{} {} {}".format(HTTP_VERSION, OK_CODE, OK))
            elif code == NOT_FOUND:
                self.__header.append("{} {} {}".format(HTTP_VERSION, NOT_FOUND_CODE, NOT_FOUND))
            elif code == ERROR:
                self.__header.append("{} {} {}".format(HTTP_VERSION, ERROR_CODE, ERROR))
            elif code == REDIRECT:
                self.__header.append("{} {} {}".format(HTTP_VERSION, REDIRECT_CODE, REDIRECT))

        # Sets the content size
        def set_content_size(self, size):
            self.__header.append("{} {}".format(CONTENT_LENGTH_HEADER, size))

        # Set the location redirect
        def set_location(self, location):
            self.__header.append("{} {}".format(LOCATION_HEADER, location))

        # Adds a header line directly
        def add_header_line(self, line):
            self.__header.append(line)

        # Ends the header
        def end_header(self):
            self.__header.append("")

        # Returns the header as a string
        def get_header(self):
            final_header = ""

            for line in self.__header:
                final_header += str(str(line) + NEW_LINE)

            return final_header

        # Clear the header
        def reset(self):
            self.__header = []

    """
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
                Embedded inner class for handling our page body
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    """

    class Body:
        # Constructor
        def __init__(self, title=DEFAULT_TITLE):
            # Privates
            self.__body = []
            self.title = title

        # Start the page, body, and give a title
        def start_body(self):
            self.__body.append("<html>")
            self.__body.append("<head><title>{}</title></head>".format(self.title))
            self.__body.append("<body>")

        # End the body and page
        def end_body(self):
            self.__body.append("</body></html>")

        # Add content to the page
        def add_content(self, text):
            self.__body.append("{}".format(text))

        # Let the page have a custom title
        def set_title(self, title):
            self.title = title

        # Returns the body as a string
        def get_body(self):
            final_body = ""

            for line in self.__body:
                final_body += str(str(line) + NEW_LINE)

            return final_body

        # Clear the body
        def reset(self):
            self.__body = []

    """
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
            Embedded inner class for holding thread variables
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    """

    class ThreadPackage:
        # Constructor
        def __init__(self, file, header, body):
            # Privates
            self.socket_file = file
            self.header = header
            self.body = body
            self.header_str = None
            self.body_str = None

    # WebServer Constructor
    def __init__(self, host, port):
        # Privates
        self.my_socket = None
        self.address = (host, port)

    """
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
                        Private instance methods
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    """

    # Show the Unsupported Request Method page
    def __show_unsupported_method_page(self, thread_package):

        """
        ---------------------------------------------------------------------
        The "Unsupported Request Method" page
        ---------------------------------------------------------------------
        """
        print("{} We received something other than GET or POST...\nShowing error page...".format(SERVER_ERROR))

        # Make the page
        thread_package.body.set_title("Unsupported Request Method")
        self.__create_page(thread_package)
        self.__add_content(thread_package, "Unsupported Request Method")

        # Set the response code, type and size.
        thread_package.header.set_http_code(ERROR)
        thread_package.header.set_content_type(HTML_CONTENT)
        thread_package.header.set_content_size(len(thread_package.body.get_body().encode(UTF)))

        self.__send_content_to_client(thread_package)

    # Show the 404 page
    def __show_not_found_page(self, thread_package):

        """
        ---------------------------------------------------------------------
        The "Error 404: Not Found" page
        ---------------------------------------------------------------------
        """
        print("{} Could not find the requested resource. Error 404.".format(SERVER_ERROR))

        # Make the page
        thread_package.body.set_title(NOT_FOUND)
        self.__create_page(thread_package)
        self.__add_content(thread_package, NOT_FOUND)

        # Set the response code, type and size.
        thread_package.header.set_http_code(NOT_FOUND)
        thread_package.header.set_content_type(HTML_CONTENT)
        thread_package.header.set_content_size(len(thread_package.body.get_body().encode(UTF)))

        self.__send_content_to_client(thread_package)

    # Show the 500 page
    def __show_internal_error_page(self, thread_package):

        """
        ---------------------------------------------------------------------
        The "Error 500: Internal Server Error" page
        ---------------------------------------------------------------------
        """
        print("{} The requested script failed. Internal Server Error. Error 500.".format(SERVER_ERROR))

        # Make the page
        thread_package.body.set_title(ERROR)
        self.__create_page(thread_package)
        self.__add_content(thread_package, ERROR)

        # Set the response code, type and size.
        thread_package.header.set_http_code(ERROR)
        thread_package.header.set_content_type(HTML_CONTENT)
        thread_package.header.set_content_size(len(thread_package.body.get_body().encode(UTF)))

        self.__send_content_to_client(thread_package)

    # Show the 301 page
    def __show_permanent_redirect(self, thread_package, uri):
        print("{} Redirecting user to {}. Error 301.".format(SERVER_LOG, uri))
        thread_package.header.set_http_code(REDIRECT)
        thread_package.header.set_location(uri)
        self.__send_content_to_client(thread_package)

    # Sends the page to the client
    def __send_content_to_client(self, thread_package, data=None):

        """
        ---------------------------------------------------------------------
        Sends the page, requested, built, or dynamically generated
        to the client for viewing.
        ---------------------------------------------------------------------
        """

        self.__finalize_page(thread_package)
        try:
            print("{} Writing contents to client...".format(SERVER_LOG))

            thread_package.socket_file.write(str(thread_package.header_str).encode())

            if data is None:
                thread_package.socket_file.write(str(thread_package.body_str).encode())
            else:
                thread_package.socket_file.write(data)

        except socket.error as e:
            print("{}".format(SERVER_ERROR), e)
        finally:
            thread_package.socket_file.close()

    # Shows the user requested page/resource
    def __send_resource(self, thread_package, path):

        """
        ---------------------------------------------------------------------
        Send a STATIC resource to the user
        ---------------------------------------------------------------------
        """

        # Set the response code, type and size.
        thread_package.header.set_http_code(OK)

        # Set the MIME type of the file
        self.__set_mime_type(thread_package, path)

        # Get the size of the file we want to serve
        thread_package.header.set_content_size(os.path.getsize(path))

        # Serve the page
        with open(path, READ_BIN) as file:
            file_content = file.read()
            self.__send_content_to_client(thread_package, file_content)

    # Executes the given script and sends output to the client
    def __execute_script(self, thread_package, path, parameters=None, length=None):
        path = str(path)

        """
        ---------------------------------------------------------------------
        We're executing a script, first tell the server it's all OK
        ---------------------------------------------------------------------
        """

        # Set the response code, type and size.
        thread_package.header.set_http_code(OK)

        # Create the arguments and execute the script
        path = "./" + path
        arguments = [path]

        # Execute the CGI script and fetch the STDOUT
        output = None
        if parameters is None:

            """
            ---------------------------------------------------------------------
            We're simply just executing a script without parameters via GET
            ---------------------------------------------------------------------
            """

            # WE are doing a simple GET execution no parameters
            # If we have any error at all, it is NOT our fault
            try:
                result = subprocess.check_output(arguments)

                # Setup the script output for parsing
                output = result.decode().split("\n")
            except Exception as e:
                """
                ---------------------------------------------------------------------
                The requested script failed
                Give the user the classic cryptic "Internal Server Error" message.
                ---------------------------------------------------------------------
                """
                self.__show_internal_error_page(thread_package)
                print("{} ".format(SERVER_ERROR) + str(e))
                return

        else:
            """
            ---------------------------------------------------------------------
            We're executing a script via POST with parameters
            ---------------------------------------------------------------------
            """
            # Set the content length of the post data
            os.environ[CONTENT_LENGTH_ENV] = str(length)

            # WE are doing a POST execution and we have parameters to pass in
            # If we have any error at all, it is NOT our fault
            std_out = None
            std_err = None
            try:
                proc_object = subprocess.Popen(
                    arguments,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE
                )
                (std_out, std_err) = proc_object.communicate(input=parameters)
            except Exception as e:
                # Do this to trigger the IF statement below...
                std_err = e

            # If the script fails, it's NOT our fault.
            if std_err is not None:
                """
                ---------------------------------------------------------------------
                The requested script failed
                Give the user the classic cryptic "Internal Server Error" message.
                ---------------------------------------------------------------------
                """
                self.__show_internal_error_page(thread_package)
                print("{} ".format(SERVER_ERROR) + str(std_err))

                # Clear the content length variable
                os.environ.pop(CONTENT_LENGTH_ENV, None)
                return
            else:
                # Setup the script output for parsing
                output = std_out.decode().split("\n")

            # Clear the content length variable
            os.environ.pop(CONTENT_LENGTH_ENV, None)

        header = True

        """
        ---------------------------------------------------------------------
        We need to append "Content-Length" to the user's script output.
        We are the server, so it is our job to tell the browser how big or 
        small our content really is.
        ---------------------------------------------------------------------
        """

        # Parse the output of the CGI script
        if output:
            for line in output:
                if line == "":
                    header = False
                    continue

                if header:
                    thread_package.header.add_header_line(line)
                else:
                    thread_package.body.add_content(line)

        # Set the size of the page and send it to the client
        thread_package.header.set_content_size(len(thread_package.body.get_body().encode(UTF)))
        self.__send_content_to_client(thread_package)

    # Process the requested URI into an actual UNIX path
    def __process_uri(self, thread_package, uri):
        slash = "/"

        """
        ---------------------------------------------------------------------
        Process the URI, turn into an actual usable UNIX path
        ---------------------------------------------------------------------
        """

        # Check to see if the resource is a directory
        if os.path.isdir(self.__get_full_path(uri)) and not uri.endswith(slash):
            uri += slash
            # Add the trailing slash, so we know it is a directory.
            self.__show_permanent_redirect(thread_package, uri)
            # Redirect to the proper directory
            return None

        # Check if they want the default page in the requested directory
        if uri.endswith(slash):
            uri += DEFAULT_PAGE

        # Remove the leading "/"
        uri = uri[SECOND_ELEMENT:]

        # Remove encoded spaces
        uri = uri.replace(ASCII_SPACE, " ")
        return uri

    # Handles the execution of the resource
    def __handle_post_script(self, thread_package, resource, parameters, length):
        resource = str(resource)
        resource = self.__process_uri(thread_package, resource)
        if not resource:
            return

        """
        ---------------------------------------------------------------------
        Execute the script with the POST parameters
        ---------------------------------------------------------------------
        """

        # Check if the resource even exists
        full_path = self.__get_full_path(resource)
        if not os.path.isfile(full_path):
            self.__show_not_found_page(thread_package)
        else:
            # Execute the script
            self.__execute_script(thread_package, resource, parameters, length)

    # Fetches the client requested resource
    def __handle_get_resource(self, thread_package, resource):
        resource = str(resource)

        """
        ---------------------------------------------------------------------
        Return or execute the requested resource
        ---------------------------------------------------------------------
        """

        # Process any query parameters with GET
        if QUESTION in resource:
            resource = self.__store_query_params(resource)

        resource = self.__process_uri(thread_package, resource)
        if not resource:
            return

        # Check if the resource even exists
        full_path = self.__get_full_path(resource)
        if not os.path.isfile(full_path):
            self.__show_not_found_page(thread_package)
        else:
            # Only send the resource to the client directly if it is a static page.
            if not resource.endswith(SCRIPT):
                self.__send_resource(thread_package, resource)
            else:
                # Execute the script
                self.__execute_script(thread_package, resource)

        # Clear the query parameters
        self.__clear_query_params()

    def __handle_single_connection(self, req_socket):

        # Get a file to write to
        socket_file = req_socket.makefile(mode=READ_WRITE_BIN)
        header = self.Header()
        body = self.Body()
        my_package = self.ThreadPackage(socket_file, header, body)

        """
        ---------------------------------------------------------------------
        Read the client's request
        ---------------------------------------------------------------------
        """
        lines = []
        for line in socket_file:
            # Grab the info from the client
            data = line.decode()
            if data == END_OF_STREAM:
                break
            lines.append(line.decode())

        """
        ---------------------------------------------------------------------
        Parse the client's request
        ---------------------------------------------------------------------
        """
        request = lines[FIRST_ELEMENT]
        method = request.split(" ")[FIRST_ELEMENT]
        resource = request.split(" ")[SECOND_ELEMENT]

        """
        ---------------------------------------------------------------------
        Read parameters sent to us by POST
        ---------------------------------------------------------------------
        """
        params = None
        length = None
        if method == POST:
            # We need to find the content-length, so we can get the POST parameters
            for line in lines:
                if line.lower().startswith(CONTENT_LENGTH_HEADER.lower()):
                    split_line = line.split(" ", 1)
                    length = int(split_line[SECOND_ELEMENT])
                    params = socket_file.read(length)
                    break

        """
        ---------------------------------------------------------------------
        Parse cookies given to us by the client
        ---------------------------------------------------------------------
        """
        # We need to find the cookie, so we can store it in the environ variables
        for line in lines:
            if line.lower().startswith(COOKIE_HEADER.lower()):
                split_line = line.split(" ", 1)
                cookies = str(split_line[SECOND_ELEMENT]).strip()
                os.environ[HTTP_COOKIE_ENV] = cookies
                break

        """
        ---------------------------------------------------------------------
        Send a reply to the client
        ---------------------------------------------------------------------
        """
        print("{} Client requesting {} via {}.".format(SERVER_LOG, resource, method))

        # Only GET and POST are supported
        if method == GET:
            os.environ[REQUEST_METHOD_ENV] = GET
            self.__handle_get_resource(my_package, resource)
        elif method == POST:
            os.environ[REQUEST_METHOD_ENV] = POST

            # We only need to pipe the parameters if the user is wanting to execute a script
            # Otherwise, the user is messing with us, and this is basically a standard GET
            if resource.endswith(SCRIPT):
                self.__handle_post_script(my_package, resource, params, length)
            else:
                self.__handle_get_resource(my_package, resource)
        else:
            # The client used something other than GET or POST...
            self.__show_unsupported_method_page(my_package)

        # Clear the environment variables
        os.environ.pop(HTTP_COOKIE_ENV, None)
        os.environ.pop(REQUEST_METHOD_ENV, None)

        # Close this threads file
        if socket_file is not None:
            socket_file.close()

    # The connection handler
    def __handle_connections(self):
        req_socket = None
        try:
            """
            ---------------------------------------------------------------------
            Listen for connections
            ---------------------------------------------------------------------
            """
            print("{} Listening at that address...".format(SERVER_LOG))
            self.my_socket.listen(socket.SOMAXCONN)
            socket_fd = self.my_socket.fileno()

            # Continuously accept connections
            while True:
                threads = []

                # We do not know how many requests the browser will send us
                while True:
                    # Block and wait for a connection, if we timeout, the browser is no longer requesting data
                    (read_fd, write_fd, error_fd) = select.select(
                        [socket_fd], [], [], TIMEOUT
                    )

                    # Handle a timeout and join all the threads
                    if not read_fd:
                        break

                    # We are still receiving requests at this point and will handle each one in parallel
                    (req_socket, addr) = self.my_socket.accept()

                    # Make a new thread and toss it into the roster
                    my_thread = Thread(target=self.__handle_single_connection, args=(req_socket,))
                    my_thread.start()
                    threads.append(my_thread)

                # Join all the threads
                for thread in threads:
                    print("{} Joining {} threads.".format(SERVER_LOG, str(len(threads))))
                    thread.join()

        except socket.error as e:
            print("{}".format(SERVER_ERROR), e)
        except KeyboardInterrupt:
            print("{} Server asked to close!\nShutting down...".format(SERVER_LOG))
        finally:
            if req_socket is not None:
                req_socket.close()
            self.my_socket.close()

    # Get the full UNIX path to the resource
    def __get_full_path(self, local_path):
        return self.__get_current_path() + "/" + local_path

    # Sets the MIME type of the file
    def __set_mime_type(self, thread_package, path):
        DELIMITER = "; "
        mime_type = None

        # Get the MIME type of the current file that we want to serve
        # Use the primary method of getting the MIME type
        mime_type = mimetypes.guess_type(path)[FIRST_ELEMENT]

        if not mime_type and platform.system() != WINDOWS:
            # Use the secondary method of getting the MIME type, if the first one didn't work.
            mime_type = self.__get_mime_type_unix(path)
            mime_type = mime_type.split(DELIMITER)[FIRST_ELEMENT]

        thread_package.header.set_content_type(mime_type)

    # Gives the MIME type of a file
    def __get_mime_type_unix(self, path):
        path = self.__get_full_path(path)
        return subprocess.check_output(["file", "-b", "--mime", path]).decode()

    """
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
                            Static class methods
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    """

    # Start the HTML page with the header
    @staticmethod
    def __create_page(thread_package):
        thread_package.body.start_body()

    # Add HTML content to the page
    @staticmethod
    def __add_content(thread_package, text):
        thread_package.body.add_content(text)

    # Output the page to the server
    @staticmethod
    def __finalize_page(thread_package):
        # End our header and body
        thread_package.header.end_header()
        thread_package.body.end_body()

        # Get the finalized header and body
        thread_package.header_str = thread_package.header.get_header()
        thread_package.body_str = thread_package.body.get_body()

        # Reset the header and body
        thread_package.header.reset()
        thread_package.body.reset()

    # Gives the current path to working directory
    @staticmethod
    def __get_current_path():
        return os.path.dirname(os.path.abspath(__file__))

    # Stores the query parameters in the environment variables
    @staticmethod
    def __store_query_params(uri):
        split_uri = uri.split(QUESTION)

        new_uri = split_uri[FIRST_ELEMENT]
        params = split_uri[SECOND_ELEMENT]

        # Store the query string
        os.environ[QUERY_STRING_ENV] = params

        # Return the stripped URI
        return new_uri

    # Clears the query parameters in the environment variables
    @staticmethod
    def __clear_query_params():
        os.environ.pop(QUERY_STRING_ENV, None)

    """
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
                            Public instance methods
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    ---------------------------------------------------------------------
    """

    # Starts the web server
    def start(self):
        try:
            """
            ---------------------------------------------------------------------
            Binds to the given address and starts listening for connections
            ---------------------------------------------------------------------
            """
            print("{} Asking the OS to bind us to: {}".format(SERVER_LOG, str(self.address)))
            self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.my_socket.bind(self.address)

            # Start the web server after we have asked the OS to bind us to the port
            self.__handle_connections()
        except socket.error as e:
            print("{}".format(SERVER_ERROR), e)
        finally:
            self.my_socket.close()


# Main routine
def main():
    my_server = WebServer(HOST, PORT)
    my_server.start()


# Main method
if __name__ == "__main__":
    main()
