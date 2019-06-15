# Sia

Sia is a network measurement and analytics library that leverages the Python data analytics stack (e.g., PANDAS, Sci-kit learn). 
As part of a software-defined network measurement stack, it lies at the control layer of that stack. Sia is named after the Egyptian 
god of foresight; appropriately named as we believe our Sia library can offer the user some insight into the behavior of their network.

Sia consists of a Python module that offers a few categories of functions:

1. Collect network data from infrastructure layer devices through several protocols (e.g., OpenTap, LLDP, SNMP)
2. Filter and split network data
3. Join network data with other data sources (e.g., IP to Geographic database)
4. Aggregate network data into other forms (e.g., flow records to traffic matrices)
5. Detect events and isolate anomalous data (e.g., network intrusions)
