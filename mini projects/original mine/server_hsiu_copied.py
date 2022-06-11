#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer # the heavy lifting of the web server
import urllib # some url parsing support
import json # support for json encoding
import sys # needed for agument handling
import random
import string
import sqlite3
import time

dbfile = 'db/clean.db'

# access_database requires the name of a sqlite3 database file and the query.
# It does not return the result of the query.
def access_database(dbfile, query):
    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    cursor.execute(query)
    connect.commit()
    connect.close()

# access_database requires the name of an sqlite3 database file and the query.
# It returns the result of the query
def access_database_with_result(dbfile, query):
    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    rows = cursor.execute(query).fetchall()
    connect.commit()
    connect.close()
    return rows


def token_generator():
    token = ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase + string.ascii_letters, k = 8))
    return token


def build_response_refill(where, what):
    """This function builds a refill action that allows part of the
       currently loaded page to be replaced."""
    return {"type":"refill","where":where,"what":what}


def build_response_redirect(where):
    """This function builds the page redirection action
       It indicates which page the client should fetch.
       If this action is used, only one instance of it should
       contained in the response and there should be no refill action."""
    return {"type":"redirect", "where":where}


def handle_validate(iuser, imagic):
    """Decide if the combination of user and magic is valid"""
    ## alter as required
    session_end = access_database_with_result(dbfile, f"SELECT u.username, s.magic FROM users u INNER JOIN session s ON u.userid = s.userid WHERE u.username='{iuser}' AND s.magic='{imagic}' AND s.end=0")
    if any(element for element in session_end):
        return True
    else:
        return False

def handle_delete_session(iuser, imagic):
    """Remove the combination of user and magic from the data base, ending the login"""
    end = int(time.time())
    session_end = access_database_with_result(dbfile, f"SELECT u.username, s.magic FROM users u INNER JOIN session s ON u.userid = s.userid WHERE u.username='{iuser}' AND s.magic='{imagic}' AND s.end=0")
    userid = session_end[0][0]
    access_database(dbfile, f"UPDATE session SET end = {end} WHERE userid = '{userid}'")
    return

def handle_login_request(iuser, imagic, parameters):
    """A user has supplied a username (parameters['usernameinput'][0])
       and password (parameters['passwordinput'][0]) check if these are
       valid and if so, create a suitable session record in the database
       with a random magic identifier that is returned.
       Return the username, magic identifier and the response action set."""
    response = []
    user = ''
    magic = ''

    if 'usernameinput' not in parameters.keys() or 'passwordinput' not in parameters.keys():
        response.append(build_response_refill('message', 'Blank username or password'))
        return [user, magic, response]
   
    username_input = parameters['usernameinput'][0]
    password_input = parameters['passwordinput'][0]
    
    login_check_query = access_database_with_result(dbfile, f"SELECT userid, username FROM users WHERE username = '{username_input}' AND password = '{password_input}'")

    if any(element for element in login_check_query):
        u_id = login_check_query[0][0]
        username = login_check_query[0][1]

        q = access_database_with_result(dbfile, f"SELECT magic FROM session WHERE userid={u_id} ORDER BY sessionid DESC LIMIT 1")
        if len(q) > 0:
            magic_token = q[0][0]
        else:
            magic_token = 0

        if handle_validate(username, magic_token) == True:
            # the user is already logged in, so end the existing session.
            handle_delete_session(username, magic_token)

        userid = login_check_query[0][0]
        user = login_check_query[0][1]
        magic = token_generator()
        start = int(time.time())

        access_database(dbfile, f"INSERT INTO session (userid, magic, start, end) VALUES ('{userid}', '{magic}', {start}, 0)")
        response.append(build_response_redirect('/page.html'))

    else: # The user is invalid
        user = ''
        magic = ''
        response.append(build_response_refill('message', 'Please enter a valid username and password.'))

    return [user, magic, response]


def handle_add_request(iuser, imagic, parameters):
    """The user has requested a vehicle be added to the count
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings) and the response action set."""
    response = []
    user = iuser
    magic = imagic

#### inputs
    location_input = parameters['locationinput'][0]
    occupancy_input = parameters['occupancyinput'][0]
    type_input = parameters['typeinput'][0]
    vehicles = {"car": 0, "van":1, "truck":2, "taxi":3, "other":4, "motorbike":5, "bicycle":6, "bus":7}

##### Checking id
    sessionid = 0
    query_session = access_database_with_result(dbfile, f"SELECT sessionid FROM session WHERE magic='{imagic}'")
    if any(element for element in query_session):
        sessionid = query_session[0][0]
    time_recorded = int(time.time())

    ## alter as required
    if handle_validate(iuser, imagic) != True:
        #Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
    
#### setup condition for invalid inputs
    elif 'locationinput' not in parameters.keys():
        response.append(build_response_refill('message', 'No location/Invalid location'))
    elif 'occupancyinput' not in parameters.keys():
        response.append(build_response_refill('message', 'No occupancy/Invalid occupancy'))
    elif 'typeinput' not in parameters.keys():
        response.append(build_response_refill('message', 'No type/Invalid type'))
    

    else: ## a valid session so process the addition of the entry.
        if not location_input:
            response.append(build_response_refill('message', 'Blank location'))
        elif type_input not in vehicles.keys():
            response.append(build_response_refill('message', 'Invalid vehicle type'))
        elif int(occupancy_input) <= 0 or int(occupancy_input) > 4:
            response.append(build_response_refill('message', 'Invalid Entry - Invalid number input'))

        elif type_input == 'bicycle':
            if int(occupancy_input) == 1:
                query_add = access_database(dbfile, f"INSERT INTO traffic (sessionid, time, type, occupancy, location, mode) VALUES ({sessionid}, {time_recorded}, 'bicycle', {occupancy_input}, '{location_input}', 1)")
                query_counter = access_database_with_result(dbfile, f"SELECT COUNT(mode) FROM traffic WHERE mode = 1 and sessionid = '{sessionid}'")
                counter = query_counter[0][0]
                response.append(build_response_refill('message', 'Entry added.'))
                response.append(build_response_refill('total', str(counter)))
            else:
                response.append(build_response_refill('message', 'Invalid occupancy input. You cannot have more than 1 person on a bicycle'))
        elif type_input == 'motorbike':
            if int(occupancy_input) <= 2 and int(occupancy_input) > 0:
                query_add = access_database(dbfile, f"INSERT INTO traffic (sessionid, time, type, occupancy, location, mode) VALUES ({sessionid}, {time_recorded}, 'motorcycle', {occupancy_input}, '{location_input}', 1)")
                query_counter = access_database_with_result(dbfile, f"SELECT COUNT(mode) FROM traffic WHERE mode = 1 and sessionid = '{sessionid}'")
                counter = query_counter[0][0]
                response.append(build_response_refill('message', 'Entry added.'))
                response.append(build_response_refill('total', str(counter)))
            else:
                response.append(build_response_refill('message', 'Invalid occupancy input. You cannot have more than 2 people on a motorbike'))
        else:            
            query_add = access_database(dbfile, f"INSERT INTO traffic (sessionid, time, type, occupancy, location, mode) VALUES ({sessionid}, {time_recorded}, '{type_input}', {occupancy_input}, '{location_input}', 1)")
            query_counter = access_database_with_result(dbfile, f"SELECT COUNT(mode) FROM traffic WHERE mode = 1 and sessionid = '{sessionid}'")
            response.append(build_response_refill('message', 'Entry added.'))
            if len(query_counter) > 0:
                counter = query_counter[0][0]
            else:
                counter = 0
                response.append(build_response_refill('message', 'Invalid inputs. Try again.'))
            response.append(build_response_refill('total', str(counter)))

    return [user, magic, response]


def handle_undo_request(iuser, imagic, parameters):
    """The user has requested a vehicle be removed from the count
       This is intended to allow counters to correct errors.
       parameters['locationinput'][0] the location to be recorded
       parameters['occupancyinput'][0] the occupant count to be recorded
       parameters['typeinput'][0] the type to be recorded
       Return the username, magic identifier (these can be empty  strings) and the response action set."""
    response = []
    user = iuser
    magic = imagic
#### inputs
    location_undo = parameters['locationinput'][0]
    occupancy_undo = parameters['occupancyinput'][0]
    type_undo = parameters['typeinput'][0]

    if 'locationinput' not in parameters.keys():
        response.append(build_response_refill('message', 'No location/Invalid location'))
    elif 'occupancyinput' not in parameters.keys():
        response.append(build_response_refill('message', 'No occupancy/Invalid occupancy'))
    elif 'typeinput' not in parameters.keys():
        response.append(build_response_refill('message', 'No type/Invalid type'))

    
    sessionid = 0
    query_session = access_database_with_result(dbfile, f"SELECT sessionid FROM session WHERE magic='{imagic}'")
    if any(element for element in query_session):
        sessionid = query_session[0][0]

    ## alter as required
    if handle_validate(iuser, imagic) != True:
        #Invalid sessions redirect to login
        response.append(build_response_redirect('/index.html'))
    else: ## a valid session so process the recording of the entry.
        find_id = access_database_with_result(dbfile, f"SELECT recordid FROM traffic WHERE location = '{location_undo}' AND occupancy = {occupancy_undo} AND type = '{type_undo}' AND sessionid = {sessionid} AND mode = 1")
        if len(find_id) > 0:
            undo_id = find_id[0][0]
            undo_time_recorded = int(time.time())
            access_database(dbfile, f"UPDATE traffic SET mode = 2 WHERE recordid = {undo_id}")
            access_database(dbfile, f"INSERT INTO traffic (sessionid, time, type, occupancy, location, mode) VALUES ({sessionid}, {undo_time_recorded}, '{type_undo}', {occupancy_undo}, '{location_undo}', 0)")
            counter = access_database_with_result(dbfile, f"SELECT COUNT(mode) FROM traffic WHERE mode = 1 and sessionid = '{sessionid}'")[0][0]
            response.append(build_response_refill('message', 'Entry Un-done.'))
            response.append(build_response_refill('total', str(counter)))
        else:
            counter = access_database_with_result(dbfile, f"SELECT COUNT(mode) FROM traffic WHERE mode = 1 and sessionid = '{sessionid}'")[0][0]
            response.append(build_response_refill('message','Invalid request, cannot find the things to undo'))
            response.append(build_response_refill('total', str(counter)))
    return [user, magic, response]


def handle_back_request(iuser, imagic, parameters):
    """This code handles the selection of the back button on the record form (page.html)
       You will only need to modify this code if you make changes elsewhere that break its behaviour"""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        response.append(build_response_redirect('/index.html'))
    else:
        response.append(build_response_redirect('/summary.html'))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_logout_request(iuser, imagic, parameters):
    """This code handles the selection of the logout button on the summary page (summary.html)
       You will need to ensure the end of the session is recorded in the database
       And that the session magic is revoked."""
    response = []
    ## alter as required
    userid = 0
    end = int(time.time())
    session_end_query = access_database_with_result(dbfile, f"SELECT u.username, s.magic FROM users u INNER JOIN session s ON u.userid = s.userid WHERE u.username='{iuser}' AND s.magic='{imagic}' AND s.end=0")
    
    if any(element for element in session_end_query):
        userid = session_end_query[0][0]
    access_database(dbfile, f"UPDATE session SET end = {end} WHERE userid = '{userid}'")
    response.append(build_response_redirect('/index.html'))
    user = ''
    magic = ''
    return [user, magic, response]


def handle_summary_request(iuser, imagic, parameters):
    """This code handles a request for an update to the session summary values.
       You will need to extract this information from the database.
       You must return a value for all vehicle types, even when it's zero."""
    response = []
    user = iuser
    magic = imagic
    ## alter as required
    if handle_validate(iuser, imagic) != True:
        response.append(build_response_redirect('/index.html'))
    else:
        no_car = access_database_with_result(dbfile, "SELECT COUNT(mode) FROM traffic WHERE mode = 1 and type = 'car'")[0][0]
        no_taxi = access_database_with_result(dbfile, "SELECT COUNT(mode) FROM traffic WHERE mode = 1 and type = 'taxi'")[0][0]
        no_bus = access_database_with_result(dbfile, "SELECT COUNT(mode) FROM traffic WHERE mode = 1 and type = 'bus'")[0][0]
        no_motorbike = access_database_with_result(dbfile, "SELECT COUNT(mode) FROM traffic WHERE mode = 1 and type = 'motorbike'")[0][0]
        no_bicycle = access_database_with_result(dbfile, "SELECT COUNT(mode) FROM traffic WHERE mode = 1 and type = 'bicycle'")[0][0]
        no_van = access_database_with_result(dbfile, "SELECT COUNT(mode) FROM traffic WHERE mode = 1 and type = 'van'")[0][0]
        no_truck = access_database_with_result(dbfile, "SELECT COUNT(mode) FROM traffic WHERE mode = 1 and type = 'truck'")[0][0]
        no_other = access_database_with_result(dbfile, "SELECT COUNT(mode) FROM traffic WHERE mode = 1 and type = 'other'")[0][0]
        no_total = access_database_with_result(dbfile, "SELECT COUNT(mode) FROM traffic WHERE mode = 1")[0][0]

        response.append(build_response_refill('sum_car', no_car))
        response.append(build_response_refill('sum_taxi', no_taxi))
        response.append(build_response_refill('sum_bus', no_bus))
        response.append(build_response_refill('sum_motorbike', no_motorbike))
        response.append(build_response_refill('sum_bicycle', no_bicycle))
        response.append(build_response_refill('sum_van', no_van))
        response.append(build_response_refill('sum_truck', no_truck))
        response.append(build_response_refill('sum_other', no_other))
        response.append(build_response_refill('total', no_total))
        user = ''
        magic = ''
    return [user, magic, response]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    # GET This function responds to GET requests to the web server.
    def do_GET(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        elif self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        elif parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, response] = handle_login_request(user_magic[0], user_magic[1], parameters)
                    #The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'add':
                    [user, magic, response] = handle_add_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, response] = handle_undo_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, response] = handle_back_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, response] = handle_summary_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, response] = handle_logout_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    response = []
                    response.append(build_response_refill('message', 'Internal Error: Command not recognised.'))

            else:
                # There was no command present, report that to the user.
                response = []
                response.append(build_response_refill('message', 'Internal Error: Command not found.'))

            text = json.dumps(response)
            print(text)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))

        elif self.path.endswith('/statistics/hours.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for /statistics/hours.csv should be handled.
            ## you should check a valid user is logged in. You are encouraged to wrap this behavour in a function.
            text = "Username,Day,Week,Month\n"
            text += "test1,0.0,0.0,0.0\n" # not real data
            text += "test2,0.0,0.0,0.0\n"
            text += "test3,0.0,0.0,0.0\n"
            text += "test4,0.0,0.0,0.0\n"
            text += "test5,0.0,0.0,0.0\n"
            text += "test6,0.0,0.0,0.0\n"
            text += "test7,0.0,0.0,0.0\n"
            text += "test8,0.0,0.0,0.0\n"
            text += "test9,0.0,0.0,0.0\n"
            text += "test10,0.0,0.0,0.0\n"       
            encoded = bytes(text, 'utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('hours.csv'))
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        elif self.path.endswith('/statistics/traffic.csv'):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for  /statistics/traffic.csv should be handled.
            ## you should check a valid user is checked in. You are encouraged to wrap this behavour in a function.
            text = "This should be the content of the csv file."
            text = "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"
            text += '"Main Road",car,0,0,0,0\n' # not real data 
            encoded = bytes(text, 'utf-8')
            self.send_response(200)
            self.send_header('Content-type', 'text/csv')
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format('traffic.csv'))
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

def run():
    """This is the entry point function to this code."""
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    if(len(sys.argv)<2): # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server on port =',sys.argv[1],'...')
    httpd.serve_forever() # This function will not return till the server is aborted.

run()

