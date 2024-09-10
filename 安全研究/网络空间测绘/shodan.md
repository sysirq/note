# Which vulnerabilities does Shodan verify?

You can get that list by using the **vuln.verified** facet and searching across all results. The facet analysis page（https://www.shodan.io/search/facet?query=net%3A0%2F0&facet=vuln.verified） of the main Shodan website can be used to see the results or you can run a command via the CLI such as **shodan stats --facets vuln.verified:100 net:0/0.**

# 搜索

```json
{
    "data": "Moxa Nport Device
            Status: Authentication disabled
            Name: NP5232I_4728
            MAC: 00:90:e8:47:10:2d",
    "ip_str": "46.252.132.235",
    "port": 4800,
    "org": "SingTel Mobile",
    "location": {
        "country_code": "SG"
    }
}
```

- data: the main response from the service itself

By default, only the **data** property is searched by Shodan.  if you wanted to search for devices on the SingTel Mobile network then a simple search for **SingTel Mobile** won't return the expected results. This is because by default, Shodan only searches the data property!

### Search Filters

Search **filters** are special keywords to tell Shodan that you wish to search specific properties. They take the format of:

```
filtername:value
```

- Note that there is no space in between the filtername and its value.
- If the value you're trying to search contains spaces then you need to wrap the value in quotes.

**Filter Reference**:https://www.shodan.io/search/filters

# Datapedia

Datapedia:https://datapedia.shodan.io/

The Datapedia describes all the metadata that Shodan crawlers gather. It is the reference document for all information about top-level properties that are available on the banner. These top-level properties contain service-specific information that provide deeper insights into the configuration and deployment of a device. Most information that Shodan collects for these services is optional which means you need to check for the existence of a property in your code before using it.

# How to Download Data with the API

### How much data can I download?

If you have an API plan then you get a certain number of **query credits** that you can spend each month. For people with the Shodan Membership that means you get 100 query credits per month while for the API plans it can range from 10,000 up to unlimited.

```
1 query credit = 100 results
```

# Programming with the Shodan API

The [CLI](https://cli.shodan.io/) should work for most purposes but sometimes you want to perform custom transformations on the banners as you're downloading them. Or you don't want to store the information in a local file. In those cases, you can use a convenient helper method provided by the Python library for Shodan called **search_cursor()** to iterate over the results:

```python
from shodan import Shodan
from shodan.cli.helpers import get_api_key

api = Shodan(get_api_key())

limit = 500
counter = 0
for banner in api.search_cursor('product:mongodb'):
    # Perform some custom manipulations or stream the results to a database
    # For this example, I'll just print out the "data" property
    print(banner['data'])
    
    # Keep track of how many results have been downloaded so we don't use up all our query credits
    counter += 1
    if counter >= limit:
        break
```


# 资料

Search Query Fundamentals

https://help.shodan.io/the-basics/search-query-fundamentals

How to Download Data with the API

https://help.shodan.io/guides/how-to-download-data-with-api

Shodan CLI

https://help.shodan.io/command-line-interface/0-installation