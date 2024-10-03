import requests
import sys
from time import strftime, sleep
import get_spiders
import shlex

VALID_SPIDERS = [x for x in get_spiders.get_spiders()]
VALID_SPIDER_NAMES = [x.vendor_name for x in VALID_SPIDERS]
print("Valid spiders:")
for spider in VALID_SPIDER_NAMES:
    print("\t- " + spider)

VALID_SPIDER_NAMES = [x.lower() for x in VALID_SPIDER_NAMES]

to_schedule = input(
    "\nPlease enter all the names of spiders you want to schedule separated by spaces. Spider names can be quoted. Or input the word 'all' to schedule all spiders.\n"
).lower()

schedule_list = shlex.split(to_schedule)
spider_list = []
for spider in schedule_list:
    if spider not in VALID_SPIDER_NAMES:
        if spider == "all":
            spider_list = VALID_SPIDERS
            break
        else:
            print(spider + " is not a valid spider name, exiting.")
            sys.exit("Invalid spider name provided.")
    else:
        spider_list.append(
            next(x for x in VALID_SPIDERS if x.vendor_name.lower() == spider)
        )

print(f"Scheduling the following spiders: {[x.vendor_name for x in spider_list]}")
for spider in spider_list:
    status_response = requests.get("http://localhost:6800/daemonstatus.json").json()
    while status_response["running"] > 0 or status_response["pending"] > 0:
        sleep_minutes = 5

        cur_time = strftime("%H:%M:%S")
        print(
            f"{cur_time}: There is still a spider running or pending, sleeping for {sleep_minutes} minutes",
        )
        sleep(sleep_minutes * 60)
        status_response = requests.get("http://localhost:6800/daemonstatus.json").json()

    response = requests.post(
        "http://localhost:6800/schedule.json",
        data={"project": "default", "spider": spider.name},
    ).json()
    if response["status"] != "ok":
        print("Got a response that is not ok, exiting")
        sys.exit(f"Response is not ok but {response}")
    else:
        print("Started " + spider.vendor_name + " with jobid " + response["jobid"])


print("Last spider scheduled, exiting.")
