from Webook.webhook import send_teams_alert ;
def main():
    
 predicted_test = int(input("Enter 1 for Dos , 2 for DDOS"))

 if predicted_test == 1 :
    send_teams_alert( title= "block Dos" , message= "Detected DoS attack. Blocking now!", theme_color= "FFFF00")
    
 elif predicted_test == 2 :
    send_teams_alert(title= "block DDos" , message= "Detected DDoS attack. Blocking now!", theme_color= "FFFF00")


if __name__ == "__main__":
    main()