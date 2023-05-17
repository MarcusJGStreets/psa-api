.. SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _sra:

Security Risk Assessment
========================

This appendix provides a Security Risk Assessment (SRA) of the |API|. It describes the threats presented by various types of adversary against the security goals for an implementation of Storage Service, and mitigating actions for those threats.

*  :secref:`sra-about` describes the assessment methodology.
*  :secref:`sra-definition` defines the security problem.
*  :secref:`sra-characterization` provides additional security design details.
*  :secref:`sra-threats` describes the threats and the recommended mitigating actions.
*  :secref:`sra-mitigations` summarizes the mitigations, and where these are implemented.

.. _sra-about:

About this assessment
---------------------

Subject and scope
^^^^^^^^^^^^^^^^^

This SRA analyses the security of the |API| itself, not of any specific implementation of the API, or any specific use of the API.

This SRA assesses implementations that correspond to the deployment architectures described in xxxxx.

Risk assessment methodology
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Our risk ratings follow the five-level version of the Arm ATG SRA methodology, which is derived
from :cite-title:`SP800-30`: for each Threat, we determine its Likelihood and the
Impact. Each is evaluated on a 5-level scale, as defined in :numref:`tab-sra-likelihood` and :numref:`tab-sra-impact`.

.. list-table:: Likelihood levels
   :name: tab-sra-likelihood
   :header-rows: 1
   :stub-columns: 1
   :widths: 1 6

   *  -  Level
      -  Definition

   *  -  Very Low
      -  Unlikely to ever occur in practice, or *mathematically near impossible*
   *  -  Low
      -  The event could occur, but only if the attacker employs *significant* resources; or it is *mathematically unlikely*
   *  -  Medium
      -  A motivated, and well-equipped adversary can make it happen within the lifetime of a product based on the feature (resp. of the feature itself)
   *  -  High
      -  Likely to happen within the lifetime of the product or feature
   *  -  Very High
      -  Will happen, and soon (for instance a zero-day)

.. list-table:: Impact levels
   :name: tab-sra-impact
   :header-rows: 1
   :stub-columns: 1
   :widths: 1 3 3

   *  -  Level
      -  Definition
      -  Example Effects

   *  -  Very Low
      -  Causes virtually no damage
      -  Probably none
   *  -  Low
      -  The damage can easily be tolerated or absorbed
      -  There would be a CVE at most
   *  -  Medium
      -  The damage will have a *noticeable* effect, such as *degrading* some functionality, but won't degrade completely the use of the considered functionality
      -  There would be a CVE at most
   *  -  High
      -  The damage will have a *strong* effect, such as causing a significant reduction in its functionality or in its security guarantees
      -  Security Analysts would discuss this at length, there would be papers, blog entries. Partners would complain
   *  -  Very High
      -  The damage will have *critical* consequences --- it could kill the feature, by affecting several of its security guarantees
      -  It would be quite an event.

         Partners would complain strongly, and delay or cancel deployment of the feature

For both Likelihood and Impact, when in doubt always choose the higher value. These two values are combined using :numref:`tab-sra-overall-risk` to determine the Overall Risk of a Threat.

.. csv-table:: Overall risk calculation
   :name: tab-sra-overall-risk
   :header-rows: 2
   :stub-columns: 1
   :align: right

   ,Impact,,,,
   Likelihood, Very Low, Low, Medium, High, Very High
   Very Low, Very Low, Very Low, Very Low, Low, Low
   Low, Very Low, Very Low, Low, Low, Medium
   Medium, Very Low, Low, Medium, Medium, High
   High, (Very) Low, Low, Medium, High, Very High
   Very High, (Very) Low, Medium, High, Very High, Very High

Threats are handled starting from the most severe ones. Mitigations will be devised for these Threats one by one (note that a Mitigation may mitigate more Threats, and one Threat may require the deployment of more than one Mitigation in order to be addressed). Likelihood and Impact will be reassessed assuming that the Mitigations are in place, resulting in a Mitigated Likelihood (this is
the value that usually decreases), a Mitigated Impact (it is less common that this value will decrease), and finally a Mitigated Risk. The Analysis is completed when all the Mitigated Risks are at the chosen residual level or lower, which usually is Low or Very Low.

The Mitigating actions that can be taken are defined in the acronym **CAST**:

*  **Control**: Put in place steps to reduce the Likelihood and/or Impact of a Threat, thereby reducing the risk to an acceptable level.
*  **Accept**: The threat is considered to be of acceptable risk such that a mitigation is not necessary, or must be accepted because of other constraint or market needs.
*  **Suppress**: Remove the feature or process that gives rise to the threat.
*  **Transfer**: Identify a more capable or suitable party to address the risk and transfer the responsibility of providing a mitigation for the threat to them.

.. _sra-definition:

Feature definition
------------------

Introduction
^^^^^^^^^^^^

Background
~~~~~~~~~~

:secref:`intro` provides the context in which the |API| is designed. 

Purpose
~~~~~~~

The |API| separates the software responsible for providing the security of the data from the calling application. The storage service call on firmware that provides low level reads and writes of non-volatile storage and the access to any required bus. 


Lifecycle
^^^^^^^^^

:numref:`fig-lifecycle` shows the typical lifecycle of a device .

.. figure:: /figure/sra-lifecycle.*
   :name: fig-lifecycle

   Device lifecycle of a system providing storage

The software implementing the secure storage , and the credentials for authorizing the storage of data, are installed or provisioned to device prior to its operational phase.

The secure storage, and the |API| are active during the operational phase, implemented within the boot-time and run-time software.



Operation and trust boundaries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following operational dataflow diagrams include all of the main components in the storage service. Presenting the context in which the |API| operates aids understanding of the threats and security mitigations, and provides justification for some of the aspects of the API design.

|API| is a C language API. Therefore, any implementation of the API must execute, at least partially, within the context of the calling application. When an implementation includes a trust boundary, the mechanism and protocol for communication across the boundary is not defined by this specification.

The operational dataflow diagram is reproduced for each of the deployment models. Although the dataflow itself is common to the models, the placement of trust boundaries is different.

It is helpful to visualize the effect of these differences on the threats against the dataflows.




Assumptions
----------

:Assumption:`Strong Isolation`


The Storage service isa PSA PROT service and must run in an isolated partition.

To comply with the PSA Security Model, the isolation MUST prevent code running in a separate partition form accessing the memory belonging to a different partition - except for defined buffers used for inter-partition communication. Similarly, it must not be possible for code in one partition too observe communication between entities in different partitions. However, it is accepted that code in a partition will have access to all the memory and communication within that partition. 

:Assumption:`One user per Partition`


The PSA APIs does not attempt to identify users and relies on the underlying run time system to provide strong identification of the partition from which a message comes. This identification is then used to establish ownership. 

In the Non-Secure Processing Environment (NSPE) there may be multiple untrusted users which are kept separate by the operating system. in this case, the PSA APIs transfer the duty of separation to the operating system in that partition. 

:Assumption:`Known Good Code`


The security model assumes that at least the code in the Root of Trust partitions (PRoT and ARoT) for verified at boot, and on any update. Therefore, it is assumed that this code is trustworthy. 

If any malicious code can run in the RoT partitions, they have full control of the device. 

:Assumption:`Secure External Storage`

For the purposes of this analysis, it is assumed that in implementation models 3 and 4, there is no way to access the stored data without going through the authenticated channel. That is, an attack that would expose the physical storage medium is beyond the resources of the attacker. 


Goals
-----

:security-goal:`Conf`
  The Storage service will ensure that no data stored can be read, except by the user that stored it.
  

:security-goal:`Integrity`
  The Storage service will ensure that data returned to a user was the data previously stored by that user. 
  
:security-goal:`Currency`
  The Storage service will ensure that data returned to a user is the most recent version of the data stored by that user.




Deployment Models
------------------

:deployment-model:`PROT`
  All storage within PRoT partition.
  
  The PRoT partition has access to an area of non-volatile storage that cannot be accessed by any other partition. The driver code resides with the PROT. 
  
  Note, while it is possible to imagine storing the data in a separate secure partition internal to the chip, there does not seem to be any security benefit to doing so, but it does introduce significant complexity. 

:deployment-model:`EXPOSED`

  Storage within internal partition - assumed to be non-secure. The Storage Service passes the data to be stored to a non-secure partition, with has access to non-volatile storage. This may be on die or external. If the storage is external, or if the bus the storage is connected to has external pins, off-chip treats need to be considered.

:deployment-model:`EXT-AUTH`
  Storage within external partition - requiring authentication.
  
  The device has access to some secure non-volatile storage that exists off-die which has a unique key. 
  
  The non-volatile storage requires authentication.  That is, all commands sent must be accompanied by a signature or MAC, made using a key known only to the device and the counter party. However, the commands are sent, and any data returned are in plain text. 
  
  There is some mechanism for provisioning the key into the storage service during manufacture. 

:deployment-model:`EXT-SC`
  Storage within external partition - capable of supporting a secure channel.
  
  Similar to Implementation 3, there is an external secure non-volatile storage device with a unique key. However, in this model, before any commands are sent, the two parties negotiate a session key and all messages are encrypted with this key. 
  
  The Secure channel must be rooted in PRoT. otherwise, it is merely a version of DM.EXPOSED.




Threats
=======

As code in the RoT partitions is assumed to be trustworthy - and any untrustworthy code running in that partition already has complete control of the device - we only consider threats from malicious actors running in non-secure partitions or external to the device. 

When considering threats we transfer the risk of protecting different users within the NSPE to the operating system, or run time within that partition.


.. threat:: Eavesdropping
   :id: EAVESDROPPING
   :deployment-models: DM.`PROT`, DM.`EXPOSED`, DM.`AUTH`, DM.`SC`

   .. description:: An attacker may be able to access data in transit.

   .. adversarial-model:: :am:`0`am:`1`am:`2`

   .. security-goal:: :SG:`CONF`

   .. unmitigated:: DM.`PROT`
      :impact: VH
      :likelihood: N\A - except for transfer of data to clients in the NSPE
      :risk: N\A
      
   The Storage service and its storage are within the PRoT partition and therefore by are definitions of an isolated partition, transferred from the PROT to another secure partition are isolated from eavesdroppers.  Under the assumptions made there is no risk of eavesdropping. However, if data is sent or returned to a client in the NSPE it is exposed. As we have noted the duty of separating users in the NSPE is TRANSFERED to the OS.

   .. unmitigated:: DM.`EXPOSED`
      :impact: VH
      :likelihood: VH
      Any adversary that can obtain Operating System privileges in the NSPE will have access to all the memory, and will therefore be able to see all data in transit.
      
   .. mitigations:: :mitigation:`Encrypt` The Storage Service must encrypt all the data to be stored before it leaves the PRoT partition. The encryption mechanism chosen must be sufficiently robust. The key used for encryption must be sufficiently protected.
      
   .. residual:: EXPOSED
      :impact: VH
      :likelihood: n/a
      :risk: n/a
      
   .. unmitigated:: EXT-AUTH
      :impact: H
      :likelihood: H

   As the commands and data are sent and received in the clear, albeit with an authorization, anyone on the bus can eavesdrop and obtain the messages. 
      
   .. mitigations:: :M.Encrypt
   
   .. residual:: EXT-AUTH
      :impact: H
      :likelihood: H
      :risk: H


   .. unmitigated:: EXT-SC
      :impact: H
      :likelihood: H
      
   If the external location is accessed without using a Secure Channel, an Adversary with access to the bus (AM.3) can trivially eavesdrop on the messages. If the Secure Channel is not rooted in the PRoT then any internal adversary (AM.1) will be able to eaves drop on traffic leaving the PRoT before it is encrypted. 
            
   .. mitigations:: :mitigation:`PRoT rooted Secure Channel` Communication with an external secure Element must be over a well-designed secure channel that is rooted inside the PRoT. The private information required to establish the channel must be suitably protected by both parties, the PRoT and the SE.  
      
   .. residual:: EXT-SC
      :impact: H
      :likelihood: n/a
      :risk: n/a

.. threat:: Man in the Middle
   :id: MITM
   :deployment-models: DM.`PROT`, DM.`EXPOSED`, DM.`AUTH`, DM.`SC`

   .. description:: An attacker can interfere with communication and replace the transmitted data. 

   .. adversarial-model:: am:`1`am:`2`

   .. security-goal:: :SG:`INTEGRITY`
   
   .. unmitigated:: DM.`PROT`
      :impact: H
      :likelihood: N\A - except for transfer of data to clients in the NSPE
      :risk: N\A

   To be "in the middle" the attacker would have to be in the PROT or in a secure partition. Any attacker that can run code in the PROT has total control of the device. Any attackr that can run code in a secure partition, has control over the functions offered by that partition. 
   
   As with T.Eavesdropping where the Storage Service is storing data for a client in the NSPE, the data is exposed within the NSPE. As noted, we TRANSFER the duty of separating clients in the NSPE to the OS running in that environment. The Storage service can only guarantee that the data is delivered to the NSPE correctly. 

   .. unmitigated:: DM.`EXPOSED`
      :impact: H
      :likelihood: H
      :risk: 

   .. mitigations:: :m.Encrypt Encryption ensures that the man in the middle does not know what data is being stored. It also means they cannot force a specific value to be stored. However they can still altar the data to be stored, rendering it to be unintelligible on decrytpion.    
    
   .. mitigations:: :mitigation:`MAC` Applying a Message Authentication Code or a signature, or using an authenticated encryption scheme means that the storage service can check the integrity of the data when it is read back from storage. A man in the middle can still deny service, but we ACCEPT this risk, as it is impossible to prevent code in the NSPE simply running a busy loop to deny service. 
    
   If the client is in the NSPE, the man in the middle can subvert all calls to the Storage Service and use some other storage If the system designer needs to be certain that the storage service is used, they must  put the calling code into a secure partition. 
    
  .. residual:: DM.`EXPOSED`
    :impact: H
    :likelihood: L
    :risk: 

  .. unmitigated:: EXT-AUTH
     :impact: H
     :likelihood: H

   .. mitigations:: :mitigation:`Verify Replies` Commands and replies are authenticated. Therefore, the man in the middle should not be able to create a valid reply indicating that the data has been stored when it has not. Provided the storage service validates replies, it can be sure that the data it sent was correctly stored, and the data retrieved is the value previously stored.  

  .. residual:: DM.`EXT-AUTH`
    :impact: H
    :likelihood: VL
    :risk: 

  .. unmitigated:: EXT-SC
     :impact: H
     :likelihood: H
     
   If the secure channel is set up using a simple Diffie-Hellman Key exchange, it would be vulnerable to a man-in-the-middle attack. Given that in this implementation we are not expecting encryption of the data - other than by the channel itself - the attacker would have full access to stored data. 
     
   .. mitigations:: :mitigation:`Authenticate endpoints` If the secure channel set up includes mutual authentication of the enclave and the Storage Service, both sides can be sure there is no MITM. This could be because the channel uses a single key known only to both parties. Or if it chooses to use an asymmetric protocol, by means of a signature with each side storing the hash of the other's public key. 

.. threat:: Direct Read Access
   :id: DRA
   :deployment-models: DM.`PROT`, DM.`EXPOSED`, DM.`AUTH`, DM.`SC`

   .. description:: An attacker might be able to read stored data through a mechanism other than the API.  

   .. adversarial-model:: am:`1`am:`2`

   .. security-goal:: :SG:CONF

   .. unmitigated:: DM.`PROT`
      :impact: H
      :likelihood: N\A
      :risk: N\A
      
   Due to the isolation of the PRoT partition, no attacker should be able to access the stored data. 

  .. unmitigated:: DM.`EXPOSED`
    :impact: H
    :likelihood: H
    :risk: 
    
   All attackers can access the data. 
    
   .. mitigations:: :m.Encrypt

  .. residual:: DM.`EXPOSED`
    :impact: H
    :likelihood: n/a
    :risk: n/a
    
  .. unmitigated:: DM.`EXT-AUTH`
    :impact: H
    :likelihood: M
    :risk: 
    
   The external device used for storage requires all accesses to be authenticated by a secret key. We assume that this key is known only to the storage device and to the PRoT. The attacker cannot form valid requests to access data. 
    
   It can however, eavesdrop on a legitimate request and replay it later.
    
   .. mitigations:: :mitigation:`Replay Protection`  if the communication protocol includes protection against replay, normally achieved by including a nonce in the construction, it will detect attempts to replay previous commands and reject them. 

  .. residual:: DM.`EXT-AUTH`
    :impact: H
    :likelihood: n/a
    :risk: 


  .. unmitigated:: DM.`EXT-SC`
    :impact: H
    :likelihood: n/a
    :risk: 
    
   The external device used for storage requires all accesses to be over the secure channel We assume that the key required to form the channel is known only to the storage device and to the PRoT. The attacker cannot form valid requests to access data. 
    
   It can however, eavesdrop on a legitimate request and replay it later.
    
   .. mitigations:: M.Replay Protection  if the communication protocol includes protection against replay, normally achieved by including a nonce in the construction, it will detect attempts to replay previous commands and reject them. 

  .. residual:: DM.`EXT-AUTH`
    :impact: H
    :likelihood: n/a
    :risk: 

.. threat:: `Direct Modification of Data` 

   :id: DMD
   :deployment-models: DM.`PROT`, DM.`EXPOSED`, DM.`AUTH`, DM.`SC`

   .. description:: An attacker might be able to modify data stored for another user.  

   .. adversarial-model:: am:`1`am:`2`

   .. security-goal:: :SG:`INTEGRITY` SG.`CURRENCY`

   .. unmitigated:: DM.`PROT`
      :impact: H
      :likelihood: N\A
      
   Due to the isolation of the PRoT partition, no attacker should be able to access the stored data. 
   However, data can be subject to accidental modification, therefore standard engineering practice - such as use of error correcting codes - should be taken to protect data.
      
   .. unmitigated:: DM.`PROT`
      :impact: H
      :likelihood: H
      
   .. mitigations:: :m.MAC
      
   All attackers can access the data. Therefore, all stored data must be authenticated, using a MAC or signature,  by the storage service within the PRoT. 
      
   ..mitigation:`Anti-rollback` A MAC by itself does not prevent an attacker from replacing one version of a file - or the entire storage area - with a previously stored version, as this would include valid signatures. Therefore, in order to prevent this attack, the storage service must keep some authentication data in a location the attacker cannot access. This location could be storage within the PRoT Partition DM.PROT or in an external secure enclave DM.ETX-AUTH or DM.EXT-SC. The data could be the root of a hash tree, or it could be a counter used with a root key to generate a version specific MAC key. In the case of a counter, some consideration should be given to the expected number of updates that will be made to the data. If we only need to offer rollback protection on firmware updates, there may only be a low number in the lifetime of the product and the counter could be stored in fuse. If we need to ensure the currency of a ganeric file store - that is regularly updated we would exhaust fuse, and may need a 32 bit counter. 

   .. residual:: DM.`PROT`
      :impact: H
      :likelihood: n/a
      
   .. unmitigated:: DM.`EXT-AUTH`
      :impact: H
      :likelihood: H
      
   .. mitigations:: m.Auth, m.Replay
      
   Without access to the Authentication key, the attacker cannot form a valid command, so the storage device will reject attempts to modify data. However, it can eavesdrop on a legitimate request and replay it later. Therefore, the communication protocol must include protection against replay. 
      
   .. residual:: DM.`EXT-AUTH`
      :impact: H
      :likelihood: n/a

   .. unmitigated:: DM.`EXT-S`
      :impact: H
      :likelihood: H
      
   .. mitigations:: m.SC, m.Replay
      
   Without access to the Authentication key, the attacker cannot form a valid command, so the storage device will reject attempts to modify data. However, it can eavesdrop on a legitimate request and replay it later. Therefore, the communication protocol must include protection against replay. 
      
   .. residual:: DM.`EXT-SC`
      :impact: H
      :likelihood: n/a

.. threat:: `Physical Replacement of storage` 

   :id: REPLACE
   :deployment-models: DM.`PROT`, DM.`EXPOSED`, DM.`AUTH`, DM.`SC`

   .. description:: An attacker might physically replace the storage medium  

   .. adversarial-model:: am.`3`

   .. security-goal:: :SG:`INTEGRITY`

   .. unmitigated:: DM.`PROT`
      :impact: N\A
      :likelihood: N\A 
      
   As the storage medium is integrated with the device, it is not possible to replace the storage. 

   .. unmitigated:: DM.`EXPOSED`
      :impact: VH
      :likelihood: H 
      
   If the storage medium is integrated with the device, it is not possible to replace the storage. However, if the data is stored on a separate device, thee is the possibility that the entire storage medium will be removed and imaged, and possibly replaced. 

   .. unmitigated:: DM.`EX-AUTH`
      :impact: VH
      :likelihood: H 
      
   The storage is external, and therefore can be replaced. 
      
   .. mitigations:: m.`uniquekeys` m.`Verify Replies`
      
   Provided that authentication keys are unique per storage device, and the Storage service verifies all replies, any attempt to replace the storage device will be detectable as the new device will not be able to form the correct responses to commands. 

   .. unmitigated:: DM.`EXT-SC`
      :impact: VH
      :likelihood: H 

   The storage is external, and therefore can be replaced. 
      
   .. mitigations:: m.`uniquekeys` m.`Authenticate endpoints`
      
   Provided that authentication keys are unique per storage device and the Storage Service correctly authenticates the en point, the replacement device will not be able to complete the handshake to set up the secure channel.


Mitigation Summary
------------------

.. list-table:: Mitigations 
   :name: tab-sra-api-mitigations
   :widths: 1 2 
   :header-rows: 1
   :class: longtable

   *  -  Implementation 
      -  Mitigations

      
   *  -  DM.`PROT`
      -  None

   *  -  DM.`EXPOSED`
      -  m.`Anti-rollback`
         m.`Encrypt` 
         m.`MAC` 
         
   *  -  DM.`EXT-AUTH`
      -  m.`Replay Protection`
         m.`uniquekeys`
         m.`Verify Replies`
         

   *  -  DM.`EXT-SC`
      -  m.`Authenticate endpoints` 
         m.`PRoT rooted Secure Channel` 
         m.`Replay Protection` 
         m.`uniquekeys` 
         m.`Verify Replies` 
         

In implementation DM.`PROT`, DM.`AUTH-SC`, the stored data can be implicitly trusted, and therefore it is not required to be encrypted or authenticated. There is also not more secure location to store verification data. However, it is possible for the data to be accidentally corrupted, therefore standard engineering practice to guard against this, for example the use of error correcting codes, should be used. 

In implementation DM.`EXPOSED`, the data can be read or modified by an attacker, therefore the storage service must provide confidentiality, integrity and authenticity by cryptographic means. The keys used to do this must be stored securely. This could be a key derived from the HUK, or separately stored in fuse in a location only readable from the PROT. 

As the attacker can always read and modify the stored data, even if they cannot actually decrypt the data. They can attempt to subvert a change by resetting the storage medium to a prior state. In order to detect this, the storage service needs to have some means of authenticating that it is reading the most recent state. 

This implies some form of authentication data stored in a location the attacker cannot modify.

In implementation DM.`EXT-AUTH`, the data can be observed, even if it cannot be modified. Therefore data stored does need to be encrypted for confidentiality. However, provided the authentication protocol is strong, and prevents replay, it should not be possible for an attacker to modify the stored data. As the store applies a MAC to each reply, the Storage service does nt need to apply extra integrity. 

In implementation DM.`EXT-SC` provided the secure channel is rooted within the PRoT. the data transferred cannot be observed ad any modification is detected. Therefore no further encryption is needed for confidentiality or integrity. 
