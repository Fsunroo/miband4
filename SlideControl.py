from miband import miband
import pyautogui as pg

class detector(miband):
    def __init__(self):
        with open("mac.txt", "r") as f:
            MAC_ADDR = f.read().strip()
            f.close()

        with open("auth_key.txt", "r") as f:
            AUTH_KEY= f.read().strip()
            f.close()
        AUTH_KEY = bytes.fromhex(AUTH_KEY)

        if (AUTH_KEY):
            self.band = miband(MAC_ADDR, AUTH_KEY, debug=True)
            success = self.band.initialize()
        
        self.stats= [None] *3
        self.state= None
        self.tempstate=None


        self.get_gyro_realtime()

        

    def detect_state(self,data):
        d=data[0]
        #print(f"{d['gyro_raw_x']}  ,  {d['gyro_raw_y']}  ,  {d['gyro_raw_z']}")
        if d['gyro_raw_x']>150:   #dast oftade
            if d['gyro_raw_y']<12:
                self.tempstate='R'
            elif d['gyro_raw_z']<-90:
                self.tempstate = 'L'
            else:
                self.tempstate='N'
        else:
            self.tempstate = 'U'
        

        if self.state ==  None:
            self.state = self.tempstate

        elif self.state == self.tempstate:
            if self.state != self.stats[-1]:
                self.stats.pop(0)
                self.stats.append(self.tempstate)
        self.state = self.tempstate

        if self.stats == ['N','L','R']:
            print('Movement Left Detected')
            pg.press('right')
            self.stats= [None] *3
        elif self.stats == ['N','R','L']:
            print('Movement Right Detected')
            pg.press('left')

            self.stats= [None] *3
        #print(self.stats)
        #print(self.tempstate)


            

    def get_gyro_realtime(self):
        self.band.start_gyro_realtime(callback=self.detect_state, sensitivity=1, avg=False)
        input('Press Enter to continue')
    

a = detector()
