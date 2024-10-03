import os
import inspect
import importlib.util
from pathlib import Path
from firmwareScraper.spiders import parent_spider


# Returns all spiders in the spiders directory that are a subclass of FirmwareScraperSpider
def get_spiders():
    spiders = []
    # The directory containing all firmwareScraper spiders
    directory = "firmwareScraper/spiders"
    # Iterate over all files in the directory
    for filename in os.listdir(Path(directory)):
        if filename.endswith(".py"):
            module_name = filename[:-3]  # Remove the .py extension
            module_path = os.path.join(directory, filename)

            # Load the module dynamically
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Iterate over all objects in the module
            for name, obj in inspect.getmembers(module):
                # Check if the object is a spider
                if inspect.isclass(obj) and issubclass(
                    obj, parent_spider.FirmwareScraperSpider
                ):
                    print("Found the class for the spider of " + obj.vendor_name)
                    spiders.append(obj)
    return spiders
