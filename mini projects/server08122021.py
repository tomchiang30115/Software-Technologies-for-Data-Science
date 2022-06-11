#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie  # some cookie handling support
from http.server import (
    BaseHTTPRequestHandler,
    HTTPServer,
)  # the heavy lifting of the web server
import urllib  # some url parsing support
import json  # support for json encoding
import sys  # needed for agument handling
import random
import string
import sqlite3
import time

dbfile = "db/clean.db"

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
    token = "".join(
        random.choices(
            string.ascii_uppercase
            + string.digits
            + string.ascii_lowercase
            + string.ascii_letters,
            k=8,
        )
    )
    return token


def build_response_refill(where, what):
    """This function builds a refill action that allows part of the
    currently loaded page to be replaced."""
    return {"type": "refill", "where": where, "what": what}


def build_response_redirect(where):
    """This function builds the page redirection action
    It indicates which page the client should fetch.
    If this action is used, only one instance of it should
    contained in the response and there should be no refill action."""
    return {"type": "redirect", "where": where}


def handle_validate(iuser, imagic):
    """Decide if the combination of user and magic is valid"""
    ## alter as required
    session_end = access_database_with_result(
        dbfile,
        f"""SELECT u.username, s.magic FROM users u
        INNER JOIN session s ON u.userid = s.userid
        WHERE u.username='{iuser}' AND s.magic='{imagic}' AND s.end=0""",
    )
    if any(element for element in session_end):
        return True
    else:
        return False


def handle_delete_session(iuser, imagic):
    """Remove the combination of user and magic from the data base, ending the login"""
    end_delete = int(time.time())
    session_end = access_database_with_result(
        dbfile,
        f"""SELECT u.username, s.magic FROM users u
        INNER JOIN session s ON u.userid = s.userid
        WHERE u.username='{iuser}' AND s.magic='{imagic}' AND s.end=0""",
    )
    userid = session_end[0][0]
    access_database(
        dbfile, f"UPDATE session SET end = {end_delete} WHERE userid = '{userid}'"
    )
    return


def handle_login_request(iuser, imagic, parameters):
    """A user has supplied a username (parameters['usernameinput'][0])
    and password (parameters['passwordinput'][0]) check if these are
    valid and if so, create a suitable session record in the database
    with a random magic identifier that is returned.
    Return the username, magic identifier and the response action set."""
    user = ""
    magic = ""
    response = []

    ############## condition blank input error msgs

    if (
        "usernameinput" not in parameters.keys()
        or "passwordinput" not in parameters.keys()
    ):
        response.append(
            build_response_refill("message", "Login error: Blank username or password")
        )
        return [user, magic, response]
    if "usernameinput" not in parameters.keys():
        response.append(build_response_refill("message", "Login error: Blank username"))
        return [user, magic, response]
    if "passwordinput" not in parameters.keys():
        response.append(build_response_refill("message", "Login error: Blank password"))

    ############### state inputs
    username_input = parameters["usernameinput"][0]
    password_input = parameters["passwordinput"][0]

    ################### filter inputs
    import re

    if username_input != " ".join(re.findall(r"[a-z0-9A-Z]+", username_input)):
        response.append(
            build_response_refill(
                "message", "Login error: Get rid of puncuations in username please"
            )
        )
        return [user, magic, response]
    elif password_input != " ".join(re.findall(r"[a-z0-9A-Z]+", password_input)):
        response.append(
            build_response_refill(
                "message", "Login error: Get rid of puncuations in password please"
            )
        )
        return [user, magic, response]

    query_login = access_database_with_result(
        dbfile,
        f"""SELECT userid, username FROM users
        WHERE username = '{username_input}'
        AND password = '{password_input}'""",
    )

    if any(element for element in query_login):
        userid = query_login[0][0]
        iuser = query_login[0][1]

        query_imagic = access_database_with_result(
            dbfile,
            f"SELECT magic FROM session WHERE userid={userid} ORDER BY sessionid DESC LIMIT 1",
        )
        if any(element for element in query_imagic):
            imagic = query_imagic[0][0]
        else:
            imagic = 0

        if handle_validate(iuser, imagic) is True:
            # the user is already logged in, so end the existing session.
            handle_delete_session(iuser, imagic)

        userid = query_login[0][0]
        user = query_login[0][1]
        magic = token_generator()
        start = int(time.time())

        access_database(
            dbfile,
            f"""INSERT INTO session (userid, magic, start, end)
                VALUES ('{userid}', '{magic}', {start}, 0)""",
        )
        response.append(build_response_redirect("/page.html"))
    else:  # If user is invalid
        user = ""
        magic = ""
        response.append(
            build_response_refill(
                "message", "Login error: Invalid username or password"
            )
        )
    return [user, magic, response]


def handle_add_request(iuser, imagic, parameters):
    """The user has requested a vehicle be added to the count
    parameters['locationinput'][0] the location to be recorded
    parameters['occupancyinput'][0] the occupant count to be recorded
    parameters['typeinput'][0] the type to be recorded
    Return the username, magic identifier (these can be empty
    strings) and the response action set."""
    response = []
    user = iuser
    magic = imagic

    #### setup condition for blank inputs
    if "locationinput" not in parameters.keys():
        response.append(
            build_response_refill(
                "message", "Location input error: No location/Invalid location"
            )
        )
        return [user, magic, response]
    elif "occupancyinput" not in parameters.keys():
        response.append(
            build_response_refill(
                "message", "Location input error: No occupancy/Invalid occupancy"
            )
        )
        return [user, magic, response]
    elif "typeinput" not in parameters.keys():
        response.append(
            build_response_refill(
                "message", "Location input error: No type/Invalid type"
            )
        )
        return [user, magic, response]

    ##### Checking id
    sessionid = 0
    query_session = access_database_with_result(
        dbfile, f"SELECT sessionid FROM session WHERE magic='{imagic}'"
    )
    if any(element for element in query_session):
        sessionid = query_session[0][0]

    time_recorded = int(time.time())

    #### inputs
    location_input = parameters["locationinput"][0]
    occupancy_input = parameters["occupancyinput"][0]
    type_input = parameters["typeinput"][0]

    vehicles = {
        "car": 0,
        "van": 1,
        "truck": 2,
        "taxi": 3,
        "other": 4,
        "motorbike": 5,
        "bicycle": 6,
        "bus": 7,
    }

    ########### input filters
    if type_input not in vehicles.keys():
        response.append(build_response_refill("message", "Invalid type"))
        return [user, magic, response]
    else:
        vehicle_values = vehicles[type_input]

    if int(occupancy_input) <= 0 or int(occupancy_input) > 4:
        response.append(
            build_response_refill(
                "message",
                "Invalid occupancy: must be greater than 0 but smaller than 4/100%",
            )
        )
        return [user, magic, response]

    import re

    if location_input != " ".join(re.findall(r"[a-z0-9A-Z]+", location_input)):
        response.append(
            build_response_refill(
                "message", "Get rid of puncuations in location please"
            )
        )
        return [user, magic, response]
    elif occupancy_input != " ".join(re.findall(r"[a-z0-9A-Z]+", occupancy_input)):
        response.append(
            build_response_refill(
                "message", "Get rid of puncuations in occupancy please"
            )
        )
        return [user, magic, response]
    elif type_input != " ".join(re.findall(r"[a-z0-9A-Z]+", type_input)):
        response.append(
            build_response_refill(
                "message", "Get rid of puncuations in vehicle type please"
            )
        )
        return [user, magic, response]

    if handle_validate(iuser, imagic) is not True:
        # Invalid sessions redirect to login
        response.append(build_response_redirect("/index.html"))
    else:  ## a valid session so process the addition of the entry.
        if type_input not in vehicles.keys():
            response.append(build_response_refill("message", "Invalid vehicle type"))
            return [user, magic, response]
        elif int(occupancy_input) <= 0 or int(occupancy_input) > 4:
            response.append(
                build_response_refill(
                    "message",
                    "Invalid occupancy: must be greater than 0 but smaller than 4/100%",
                )
            )
            return [user, magic, response]
        else:
            query_add = access_database(
                dbfile,
                f"""INSERT INTO traffic (sessionid, time, type, occupancy, location, mode)
                VALUES ({sessionid}, {time_recorded}, {vehicle_values},
                {occupancy_input}, '{location_input}', 1)""",
            )
            query_counter = access_database_with_result(
                dbfile,
                f"SELECT COUNT(mode) FROM traffic WHERE mode = 1 and sessionid = '{sessionid}'",
            )
            response.append(build_response_refill("message", "Entry added."))
            if any(element for element in query_counter):
                counter = query_counter[0][0]
            else:
                counter = 0
                response.append(build_response_refill("message", "Invalid inputs"))
            response.append(build_response_refill("total", str(counter)))

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

    ############# Check for blank input first before setting input variables

    if "locationinput" not in parameters.keys():
        response.append(
            build_response_refill(
                "message", "Specify location/Invalid location before undo-ing"
            )
        )
        return [user, magic, response]
    elif "occupancyinput" not in parameters.keys():
        response.append(
            build_response_refill("message", "No occupancy/Invalid occupancy")
        )
        return [user, magic, response]
    elif "typeinput" not in parameters.keys():
        response.append(build_response_refill("message", "No type/Invalid type"))
        return [user, magic, response]

    ##################################### session id check
    sessionid = 0
    query_session = access_database_with_result(
        dbfile, f"SELECT sessionid FROM session WHERE magic='{imagic}'"
    )
    if any(element for element in query_session):
        sessionid = query_session[0][0]

    ################################################ inputs
    location_undo = parameters["locationinput"][0]
    occupancy_undo = parameters["occupancyinput"][0]
    type_undo = parameters["typeinput"][0]
    vehicles = {
        "car": 0,
        "van": 1,
        "truck": 2,
        "taxi": 3,
        "other": 4,
        "motorbike": 5,
        "bicycle": 6,
        "bus": 7,
    }

    if type_undo not in vehicles.keys():
        response.append(build_response_refill("message", "Invalid type"))
        return [user, magic, response]
    else:
        vehicle_values_undo = vehicles[type_undo]

    if int(occupancy_undo) <= 0 or int(occupancy_undo) > 4:
        response.append(
            build_response_refill(
                "message",
                "Invalid occupancy: must be greater than 0 but smaller than 4/100%",
            )
        )
        return [user, magic, response]

    if handle_validate(iuser, imagic) is not True:
        # Invalid sessions redirect to login
        response.append(build_response_redirect("/index.html"))
    else:  ## a valid session so process the recording of the entry.
        find_id = access_database_with_result(
            dbfile,
            f"""SELECT recordid FROM traffic 
            WHERE location = '{location_undo}' AND
            occupancy = {occupancy_undo} AND
            type = {vehicle_values_undo} AND
            sessionid = {sessionid} AND
            mode = 1""",
        )
        if any(element for element in find_id):
            undo_id = find_id[0][0]
            undo_time_recorded = int(time.time())
            access_database(
                dbfile, f"UPDATE traffic SET mode = 2 WHERE recordid = {undo_id}"
            )
            access_database(
                dbfile,
                f"""INSERT INTO traffic (sessionid, time, type, occupancy, location, mode)
                VALUES ({sessionid}, {undo_time_recorded},
                {vehicle_values_undo}, {occupancy_undo}, '{location_undo}', 0)""",
            )
            counter = access_database_with_result(
                dbfile,
                f"SELECT COUNT(mode) FROM traffic WHERE mode = 1 and sessionid = '{sessionid}'",
            )[0][0]
            response.append(build_response_refill("message", "Entry Un-done."))
            response.append(build_response_refill("total", str(counter)))
        else:
            counter = access_database_with_result(
                dbfile,
                f"SELECT COUNT(mode) FROM traffic WHERE mode = 1 and sessionid = '{sessionid}'",
            )[0][0]
            response.append(
                build_response_refill(
                    "message", "Invalid request, cannot find the things to undo"
                )
            )
            response.append(build_response_refill("total", str(counter)))
    return [user, magic, response]


def handle_back_request(iuser, imagic, parameters):
    """This code handles the selection of the back button on the record form (page.html)
    You will only need to modify this code if you make changes elsewhere that break its behaviour"""
    response = []
    ## alter as required
    if handle_validate(iuser, imagic) is not True:
        response.append(build_response_redirect("/index.html"))
    else:
        response.append(build_response_redirect("/summary.html"))
    user = ""
    magic = ""
    return [user, magic, response]


def handle_logout_request(iuser, imagic, parameters):
    """This code handles the selection of the logout button on the summary page (summary.html)
    You will need to ensure the end of the session is recorded in the database
    And that the session magic is revoked."""
    response = []
    ## alter as required

    end_logout = int(time.time())

    access_database(
        dbfile, f"UPDATE session SET end = {end_logout} WHERE magic = '{imagic}'"
    )

    user = ""
    magic = ""
    response.append(build_response_redirect("/index.html"))
    return [user, magic, response]


def handle_summary_request(iuser, imagic, parameters):
    """This code handles a request for an update to the session summary values.
    You will need to extract this information from the database.
    You must return a value for all vehicle types, even when it's zero."""
    response = []
    user = iuser
    magic = imagic

    sessionid = 0
    query_session = access_database_with_result(
        dbfile, f"SELECT sessionid FROM session WHERE magic='{imagic}'"
    )
    if any(element for element in query_session):
        sessionid = query_session[0][0]

    ## alter as required
    if handle_validate(iuser, imagic) is not True:
        response.append(build_response_redirect("/index.html"))
    else:

        def count_summary(vehicle_types, sessionid):
            return access_database_with_result(
                dbfile,
                f"""SELECT COUNT(t.recordid) FROM traffic t
            INNER JOIN session s ON t.sessionid = s.sessionid
            WHERE mode = 1 AND type = {vehicle_types} AND t.sessionid = {sessionid}""",
            )

        car = 0
        taxi = 3
        bus = 7
        motorbike = 5
        bicycle = 6
        van = 1
        truck = 2
        other = 4

        no_car = count_summary(car, sessionid)
        no_taxi = count_summary(taxi, sessionid)
        no_bus = count_summary(bus, sessionid)
        no_motorbike = count_summary(motorbike, sessionid)
        no_bicycle = count_summary(bicycle, sessionid)
        no_van = count_summary(van, sessionid)
        no_truck = count_summary(truck, sessionid)
        no_other = count_summary(other, sessionid)

        no_total = access_database_with_result(
            dbfile,
            f"""SELECT COUNT(t.recordid) FROM traffic t
            INNER JOIN session s ON t.sessionid = s.sessionid
            WHERE mode = 1 AND t.sessionid = {sessionid}""",
        )[0][0]

        response.append(build_response_refill("sum_car", no_car))
        response.append(build_response_refill("sum_taxi", no_taxi))
        response.append(build_response_refill("sum_bus", no_bus))
        response.append(build_response_refill("sum_motorbike", no_motorbike))
        response.append(build_response_refill("sum_bicycle", no_bicycle))
        response.append(build_response_refill("sum_van", no_van))
        response.append(build_response_refill("sum_truck", no_truck))
        response.append(build_response_refill("sum_other", no_other))
        response.append(build_response_refill("total", no_total))
        user = ""
        magic = ""
    return [user, magic, response]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    # GET This function responds to GET requests to the web server.
    def do_GET(self):
        from datetime import datetime, time
        from dateutil import relativedelta

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie["u_cookie"] = user
            x.send_header("Set-Cookie", ucookie.output(header="", sep=""))
            mcookie = Cookie.SimpleCookie()
            mcookie["m_cookie"] = magic
            x.send_header("Set-Cookie", mcookie.output(header="", sep=""))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get("Cookie"))
            user = ""
            magic = ""
            for keyc, valuec in rcookies.items():
                if keyc == "u_cookie":
                    user = valuec.value
                if keyc == "m_cookie":
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
        if self.path.startswith("/css"):
            self.send_response(200)
            self.send_header("Content-type", "text/css")
            self.end_headers()
            with open("." + self.path, "rb") as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        elif self.path.startswith("/js"):
            self.send_response(200)
            self.send_header("Content-type", "text/js")
            self.end_headers()
            with open("." + self.path, "rb") as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("./index.html", "rb") as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith(".html"):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("." + parsed_path.path, "rb") as file:
                self.wfile.write(file.read())
            file.close()

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        elif parsed_path.path == "/action":
            self.send_response(200)  # respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if "command" in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters["command"][0] == "login":
                    [user, magic, response] = handle_login_request(
                        user_magic[0], user_magic[1], parameters
                    )
                    # The result of a login attempt will be to set the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters["command"][0] == "add":
                    [user, magic, response] = handle_add_request(
                        user_magic[0], user_magic[1], parameters
                    )
                    if (
                        user == "!"
                    ):  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, "", "")
                elif parameters["command"][0] == "undo":
                    [user, magic, response] = handle_undo_request(
                        user_magic[0], user_magic[1], parameters
                    )
                    if (
                        user == "!"
                    ):  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, "", "")
                elif parameters["command"][0] == "back":
                    [user, magic, response] = handle_back_request(
                        user_magic[0], user_magic[1], parameters
                    )
                    if (
                        user == "!"
                    ):  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, "", "")
                elif parameters["command"][0] == "summary":
                    [user, magic, response] = handle_summary_request(
                        user_magic[0], user_magic[1], parameters
                    )
                    if (
                        user == "!"
                    ):  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, "", "")
                elif parameters["command"][0] == "logout":
                    [user, magic, response] = handle_logout_request(
                        user_magic[0], user_magic[1], parameters
                    )
                    if (
                        user == "!"
                    ):  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, "", "")
                else:
                    # The command was not recognised, report that to the user.
                    response = []
                    response.append(
                        build_response_refill(
                            "message", "Internal Error: Command not recognised."
                        )
                    )

            else:
                # There was no command present, report that to the user.
                response = []
                response.append(
                    build_response_refill(
                        "message", "Internal Error: Command not found."
                    )
                )

            text = json.dumps(response)
            print(text)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(text, "utf-8"))

        elif self.path.endswith("/statistics/hours.csv"):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for /statistics/hours.csv should be handled.
            ## you should check a valid user is logged in. You are encouraged to wrap this behavour in a function.

            response = []
            iuser = user_magic[0]
            imagic = user_magic[1]

            if handle_validate(iuser, imagic) is not True:
                # Invalid sessions redirect to login
                response.append(build_response_redirect("/index.html"))
            else:
                midnight_2359 = datetime.combine(datetime.now(), time.max)

                one_day = relativedelta.relativedelta(days=1)
                one_week = relativedelta.relativedelta(weeks=1)
                one_month = relativedelta.relativedelta(months=1)

                yesterday_date = int((midnight_2359 - one_day).timestamp())
                last_week_date = int((midnight_2359 - one_week).timestamp())
                last_month_date = int((midnight_2359 - one_month).timestamp())

                last_24h = access_database_with_result(
                    dbfile,
                    f"""SELECT u.username, SUM(s.end-s.start) FROM session s
                    INNER JOIN users u ON u.userid = s.userid
                    WHERE s.end > 0 AND (s.start <= {int(midnight_2359.timestamp())}) AND
                    (s.start >= {yesterday_date}) GROUP BY u.username""",
                )
                last_week_to_today = access_database_with_result(
                    dbfile,
                    f"""SELECT u.username, SUM(s.end-s.start) FROM session s
                    INNER JOIN users u ON u.userid = s.userid
                    WHERE s.end > 0 AND (s.start <= {int(midnight_2359.timestamp())}) AND
                    (s.start >= {last_week_date}) GROUP BY u.username""",
                )
                last_month_to_today = access_database_with_result(
                    dbfile,
                    f"""SELECT u.username, SUM(s.end-s.start) FROM session s
                    INNER JOIN users u ON u.userid = s.userid
                    WHERE s.end > 0 AND (s.start <= {int(midnight_2359.timestamp())}) AND
                    (s.start >= {last_month_date}) GROUP BY u.username""",
                )

                text = "Username,Day,Week,Month\n"

                for i in range(len(last_24h)):
                    text += f"{last_24h[i][0]},{(last_24h[i][1] / (3600)):.1f},{(last_week_to_today[i][1] / (3600)):.1f},{(last_month_to_today[i][1] / (3600)):.1f}\n"

                users_with_hours_worked = []
                for j in range(len(last_24h)):
                    users_with_hours_worked.append(last_24h[j][0])

                list_of_users = access_database_with_result(
                    dbfile, f"SELECT u.username FROM users u"
                )

                users_with_no_hours = []
                for k in list_of_users:
                    if k[0] not in users_with_hours_worked:
                        users_with_no_hours.append(k[0])

                if any(element for element in users_with_no_hours):
                    for users in users_with_no_hours:
                        text += f"{users},0.0,0.0,0.0\n"

            encoded = bytes(text, "utf-8")
            self.send_response(200)
            self.send_header("Content-type", "text/csv")
            self.send_header(
                "Content-Disposition", 'attachment; filename="{}"'.format("hours.csv")
            )
            self.send_header("Content-Length", len(encoded))
            self.end_headers()
            self.wfile.write(encoded)

        elif self.path.endswith("/statistics/traffic.csv"):
            ## if we get here, the user is looking for a statistics file
            ## this is where requests for  /statistics/traffic.csv should be handled.
            ## you should check a valid user is checked in. You are encouraged to wrap this behavour in a function.

            response = []
            iuser = user_magic[0]
            imagic = user_magic[1]

            if handle_validate(iuser, imagic) is not True:
                # Invalid sessions redirect to login
                response.append(build_response_redirect("/index.html"))
            else:
                query_latest_entry = access_database_with_result(
                    dbfile, f"""SELECT MAX(time) from traffic"""
                )[0][0]

                most_recent_entry_time = datetime.fromtimestamp(query_latest_entry)

                most_recent = int(
                    datetime.combine(most_recent_entry_time, time.min).timestamp()
                )

                query_traffic_csv = access_database_with_result(
                    dbfile,
                    f"""SELECT location, type,
                    COUNT(occupancy=1 OR NULL),
                    COUNT(occupancy=2 OR NULL),
                    COUNT(occupancy=3 OR NULL),
                    COUNT(occupancy=4 OR NULL)
                    FROM traffic
                    WHERE time > {most_recent}
                    GROUP BY location, type""",
                )
                query_traffic_list_of_list = [
                    list(element) for element in query_traffic_csv
                ]
                vehicles = {
                    0: "car",
                    1: "van",
                    2: "truck",
                    3: "taxi",
                    4: "other",
                    5: "motorbike",
                    6: "bicycle",
                    7: "bus",
                }

                text = "Location,Type,Occupancy1,Occupancy2,Occupancy3,Occupancy4\n"
                for i in range(len(query_traffic_csv)):
                    query_traffic_list_of_list[i][1] = vehicles[query_traffic_csv[i][1]]

                    location_csv = query_traffic_csv[i][0]
                    type_csv = query_traffic_list_of_list[i][1]

                    occupancy1 = query_traffic_csv[i][2]
                    occupancy2 = query_traffic_csv[i][3]
                    occupancy3 = query_traffic_csv[i][4]
                    occupancy4 = query_traffic_csv[i][5]

                    text += f"'{location_csv}','{type_csv}'',{occupancy1},{occupancy2},{occupancy3},{occupancy4}\n"

            encoded = bytes(text, "utf-8")
            self.send_response(200)
            self.send_header("Content-type", "text/csv")
            self.send_header(
                "Content-Disposition", 'attachment; filename="{}"'.format("traffic.csv")
            )
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
    print("starting server...")
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    if len(sys.argv) < 2:  # Check we were given both the script name and a port number
        print("Port argument not provided.")
        return
    server_address = ("127.0.0.1", int(sys.argv[1]))
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print("running server on port =", sys.argv[1], "...")
    httpd.serve_forever()  # This function will not return till the server is aborted.


run()
