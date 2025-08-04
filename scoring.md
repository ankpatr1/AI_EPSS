*How to calculate the CVSS Score*
In the site we have impact level i.e :
    0< 3 ---LOW 
    3 to 6 -- medium 
    and 6 to 9 or above is : High 
* let us know abut how to calculate these cvss what we are seen in the website .
*Base Score Metrics*
* Network (AV:N): application is in the public internet 
* Adjacent Network (AV:A):We would select when the application is part of a private Network  Example : Office network 
* Local (AV:L): local access to the application . that means if we have run some code and through that we can receive access of that device . 
* Physical (AV:P):we can just walk in we have the device
**Attack Complexity (AC)**
* low : how complex the attack -> if the attacker is easy to do the attack then its low 
* high:  any effort then its high 
**Privileges Required (PR)**
* None :Don't require any authentication and any privilege inside the application 
* Low :Its require a low privilege user  
* High :Its Admit level who is having good authority 
**User Interaction (UI)** : is it required or not -: 
* None : do you required user interaction 
* required : it required 
**scopes**
* Unchanged : It can only affect the resources managed by the same authority or the same user in that case the scope is unchanged 
* changed : if nit you can mark it as change 
*Imapct Metrics* 
**Confidentiality Impact**
When you have some data you would want it to be confidential you would want that only the person who is intended to have that information should be able to see that information 
* None: no one 
* low: visible but bot controlled or not cause any serious loss 
* High: there is serious loss ex card info 
**Integrity** correct data if track these data and ry to impact 
* None : imposition or no modify much 
* Low : there was s ome modification 
* High : data is imp , modify 

**Avalability** 
* non : not impact 
* low : dinal service not for longer period time or not imp 
* high : nothing avaliable 

**We can see CVSS score we can put only use base score matrics .
example :  select matrics -> and see the score 

CVSS v3.1 Vector
AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:L

*Temporal Score Metrics*
**Exploit Code Maturity (E)**
* Not Defined : Is there any code ? if not you mentioned this  
* Unporoven that Exploit Exist : Not Exploit code is avaliable or is this theoretical 
* Proof Of concept code : 
* Functional Exploit exits :have code but 
  
**Remediation Level(RL)**
* Not Defined :
* Official fix : 
* Temporary Fix :
* Workaround : 
* Unavailable :
**Report Confidence**
