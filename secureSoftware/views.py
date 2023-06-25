from django.shortcuts import render, redirect
from . import eccV
from . import models
import ast


SIGN_MESSAGE = {'message':'Failed'}
VERIFICATION_MESSAGE = {'message':'Resubmit for processing'}

def home(request):
    return render(request,'thePage.html',{'message':"Hello, there"})

def process_file(request):
    if request.method == 'POST':
        uploaded_file = request.FILES['file']
        if 'sign' in request.POST:
            message = signing(uploaded_file)
            SIGN_MESSAGE['message'] = message
            return redirect("sign/")
        
        elif 'verify' in request.POST:
            message = verifying(uploaded_file)
            VERIFICATION_MESSAGE['message'] = message
            return redirect("verify/")

def sign_software(request):
    return render(request,'message.html',{'message':SIGN_MESSAGE['message'] })

def verify_software(request):
    return render(request,'message.html',{'message':VERIFICATION_MESSAGE['message']})

def signing(file):
    file_content = file.read()
    hashed_file = eccV.hash_message(file_content)
    signature = eccV.sign_message(eccV.private_key,hashed_file)
    signedSoftware = models.Software()
    signedSoftware.signature = signature
    signedSoftware.public_key = eccV.public_key
    signedSoftware.save()
    file.close()
    return "signed"

def verifying(file):
    file_content = file.read()
    hashed_file = eccV.hash_message(file_content)

    all_entries = models.Software.objects.all()

    validity = False
    for entry in all_entries:
        signature = ast.literal_eval(entry.signature)
        public_key = ast.literal_eval(entry.public_key)
        print(type(public_key))
        validity = eccV.verify_signature(public_key,hashed_file,signature)
        if validity == True:
            break
    
    if validity:
        return "valid software"
    
    return "Invalid or not_registered software"
