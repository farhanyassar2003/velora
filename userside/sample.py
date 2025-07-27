import smtplib

server = smtplib.SMTP("smtp.gmail.com", 587)
server.starttls()
server.login("farhanyassar2003@gmail.com", "kftl tyku dwgy xotv")
print("Success!")
