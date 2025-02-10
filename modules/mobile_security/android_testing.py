import frida


class AndroidTester:
    """
    Initializes an instance of the AndroidTester class.
    Parameters:
        target_app (str): The target application to be tested.
    """
    """
    Runs the Frida script to perform security testing on the target application.
    """

    def __init__(self, target_app):
        self.target_app = target_app

    def run_frida_script(self):
        session = frida.get_usb_device().attach(self.target_app)
        script = session.create_script("""
        Java.perform(function() {
            var Activity = Java.use('android.app.Activity');
            Activity.onResume.implementation = function() {
                console.log("Uygulama aktif oldu");
                this.onResume();
            };
        });
        """)
        script.load()
