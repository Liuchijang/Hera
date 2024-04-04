import os
import re
import string

PRINTABLE_CHARS = set(string.printable)

def write_output(bindings_dict, consumer_dict, filter_dict, outputFolder):
    # Write output to specified file 
    filepath = os.path.join(outputFolder,"wmi-module-output.txt")
    print(f"Saved output in {filepath}")
    with open(filepath, "w") as file:
        file.write("    Bindings:\n")
        for binding_name, binding_details in bindings_dict.items():
            if (
                    "BVTConsumer-BVTFilter" in binding_name or
                    "SCM Event Log Consumer-SCM Event Log Filter" in binding_name):
                file.write(
                    "        {}\n                (Common binding based on consumer and filter names,"
                    " possibly legitimate)".format(binding_name))
            else:
                file.write("        {}".format(binding_name))
            event_filter_name = binding_details["event_filter_name"]
            event_consumer_name = binding_details["event_consumer_name"]

            # Print binding details if available
            if consumer_dict[event_consumer_name]:
                for event_consumer_details in consumer_dict[event_consumer_name]:
                    file.write("\n            Consumer: {}".format(event_consumer_details))
            else:
                file.write("\n            Consumer: {}".format(event_consumer_name))

            # Print details for each filter found for this filter name
            for event_filter_details in filter_dict[event_filter_name]:
                file.write("\n            Filter: {}".format(event_filter_details))
                file.write("")

def print_output(bindings_dict, consumer_dict, filter_dict):
    print("    Bindings:\n")
    for binding_name, binding_details in bindings_dict.items():
        if (
                "BVTConsumer-BVTFilter" in binding_name or
                "SCM Event Log Consumer-SCM Event Log Filter" in binding_name):
            print(
                "        {}\n                (Common binding based on consumer and filter names,"
                " possibly legitimate)".format(binding_name))
        else:
            print("        {}".format(binding_name))
        event_filter_name = binding_details["event_filter_name"]
        event_consumer_name = binding_details["event_consumer_name"]

        # Print binding details if available
        if consumer_dict[event_consumer_name]:
            for event_consumer_details in consumer_dict[event_consumer_name]:
                print("\n            Consumer: {}".format(event_consumer_details))
        else:
            print("\n            Consumer: {}".format(event_consumer_name))

        # Print details for each filter found for this filter name
        for event_filter_details in filter_dict[event_filter_name]:
            print("\n            Filter: {}".format(event_filter_details))
            print("")


def parse_WMI_output(consumer_dict):
    consumer_list = []
    for key in consumer_dict.keys():
        # whitelisting known legit WMI consumer
        if "SCM Event Log Consumer" in str(consumer_dict[key]) or "BVTConsumer" in str(consumer_dict[key]):
            continue
        consumer = "".join(consumer_dict[key]).split("\n\t\t")
        consumerInstance = {}
        for i in consumer:
            if i.strip():
                key, value = i.split(":", 1)
                if key == "Arguments":
                    value = "".join(eval(value))
                    consumerInstance[key.strip()] = value.strip()
                else: consumerInstance[key.strip()] = value.strip()
        consumer_list.append(consumerInstance)
    return consumer_list

def wmi_module(inputFolder, outputFolder = None, verbose=False, savefile=False):
    print("+"*50 + "\nWMI scanning...")
    """Main function for everything!"""

    # print("\n    Enumerating FilterToConsumerBindings...")

    #Read objects.data 4 lines at a time to look for bindings
    objects_file = open(f"{inputFolder}\\OBJECTS.DATA", "rb")
    current_line = objects_file.readline()
    lines_list = [current_line]
    current_line = objects_file.readline()
    lines_list.append(current_line)
    current_line = objects_file.readline()
    lines_list.append(current_line)
    current_line = objects_file.readline()
    lines_list.append(current_line)

    #Precompiled match objects to search each line with
    event_consumer_mo = re.compile(r"([\w\_]*EventConsumer\.Name\=\")([\w\s]*)(\")")
    event_filter_mo = re.compile(r"(_EventFilter\.Name\=\")([\w\s]*)(\")")

    #Dictionaries that will store bindings, consumers, and filters
    bindings_dict = {}
    consumer_dict = {}
    filter_dict = {}

    while current_line:
        # Join all the read lines together (should always be 4) to look for bindings spread over
        #   multiple lines that may have been one page
        decoded_lines = [line.decode("latin-1") for line in lines_list]
        potential_page = " ".join(decoded_lines)

        # Look for FilterToConsumerBindings
        if "_FilterToConsumerBinding" in potential_page:
            if (
                    re.search(event_consumer_mo, potential_page) and
                    re.search(event_filter_mo, potential_page)):
                event_consumer_name = re.search(event_consumer_mo, potential_page).groups(0)[1]
                event_filter_name = re.search(event_filter_mo, potential_page).groups(0)[1]

                #Add the consumers and filters to their dicts if they don't already exist
                #set() is used to avoid duplicates as we go through the lines
                if event_consumer_name not in consumer_dict:
                    consumer_dict[event_consumer_name] = set()
                if event_filter_name not in filter_dict:
                    filter_dict[event_filter_name] = set()

                #Give the binding a name and add it to the dict
                binding_id = "{}-{}".format(event_consumer_name, event_filter_name)
                if binding_id not in bindings_dict:
                    bindings_dict[binding_id] = {
                        "event_consumer_name":event_consumer_name,
                        "event_filter_name":event_filter_name}

        # Increment lines and look again
        current_line = objects_file.readline()
        lines_list.append(current_line)
        lines_list.pop(0)

    # Close the file and look for consumers and filters
    objects_file.close()
    print("    {} FilterToConsumerBinding(s) Found."
          .format(len(bindings_dict)))
    # Read objects.data 4 lines at a time to look for filters and consumers
    objects_file = open(f"{inputFolder}\\OBJECTS.DATA", "rb")
    current_line = objects_file.readline()
    lines_list = [current_line]
    current_line = objects_file.readline()
    lines_list.append(current_line)
    current_line = objects_file.readline()
    lines_list.append(current_line)
    current_line = objects_file.readline()
    lines_list.append(current_line)

    while current_line:
        decoded_lines = [line.decode("latin-1") for line in lines_list]
        potential_page = " ".join(decoded_lines).replace("\n", "")

        # Check each potential page for the consumers we are looking for
        if "EventConsumer" in potential_page:
            for event_consumer_name, event_consumer_details in consumer_dict.items():
                # Can't precompile regex because it is dynamically created with each consumer name
                if "CommandLineEventConsumer" in potential_page:
                    consumer_mo = re.compile("(CommandLineEventConsumer)(\x00\x00)(.*?)(\x00)(.*?)"
                                             "({})(\x00\x00)?([^\x00]*)?"
                                             .format(event_consumer_name))
                    consumer_match = re.search(consumer_mo, potential_page)
                    if consumer_match:
                        noisy_string = consumer_match.groups()[2]
                        consumer_details = "\n\t\tConsumer Type: {}\n\t\tArguments:     {}".format(
                            consumer_match.groups()[0],
                            [event_consumer_name for event_consumer_name in noisy_string if event_consumer_name in
                                   PRINTABLE_CHARS])
                        if consumer_match.groups()[5]:
                            consumer_details += "\n\t\tConsumer Name: {}".format(consumer_match.groups()[5])
                        if consumer_match.groups()[7]:
                            consumer_details += "\n\t\tOther:         {}".format(consumer_match.groups()[7])
                        consumer_dict[event_consumer_name].add(consumer_details)

                else:
                    consumer_mo = re.compile(
                        r"(\w*EventConsumer)(.*?)({})(\x00\x00)([^\x00]*)(\x00\x00)([^\x00]*)"
                        .format(event_consumer_name))
                    consumer_match = re.search(consumer_mo, potential_page)
                    if consumer_match:
                        consumer_details = "{} ~ {} ~ {} ~ {}".format(
                            consumer_match.groups()[0],
                            consumer_match.groups()[2],
                            consumer_match.groups()[4],
                            consumer_match.groups()[6])
                        consumer_dict[event_consumer_name].add(consumer_details)

        # Check each potential page for the filters we are looking for
        for event_filter_name, event_filter_details in filter_dict.items():
            if event_filter_name in potential_page:
                # Can't precompile regex because it is dynamically created with each filter name
                filter_mo = re.compile(
                    r"({})(\x00\x00)([^\x00]*)(\x00\x00)".format(event_filter_name))
                filter_match = re.search(filter_mo, potential_page)
                if filter_match:
                    filter_details = "\n\t\tFilter name:  {}\n\t\tFilter Query: {}".format(
                        filter_match.groups()[0],
                        filter_match.groups()[2])
                    filter_dict[event_filter_name].add(filter_details)

        current_line = objects_file.readline()
        lines_list.append(current_line)
        lines_list.pop(0)
    objects_file.close()
    # write results to file. 
    if savefile:
        write_output(bindings_dict,consumer_dict,filter_dict,outputFolder)
    #print result to screen
    if verbose:
        print_output(bindings_dict,consumer_dict,filter_dict)
    result = parse_WMI_output(consumer_dict)
    print("Scan WMI repository completed.")
    return result

if __name__ == "__main__":
    wmi_module()

