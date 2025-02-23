from pyflowmeter.sniffer import create_sniffer
import time


sniffer = create_sniffer(
            input_interface="Wi-Fi",
            verbose=True,
            to_csv=True,
            output_file='./flows_test.csv',
        
        )

sniffer.start() 
time.sleep(10)
sniffer.stop()
