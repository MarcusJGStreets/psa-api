.. SPDX-FileCopyrightText: Copyright 2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _sra:

Security Risk Assessment
========================

This appendix provides a Security Risk Assessment (SRA) of the |API| and of a generic implementation of storage. It describes the threats presented by various types of adversaries against the
security goals for an implementation of Storage Service, and mitigating actions
for those threats.

*  :secref:`sra-about` describes the assessment methodology.
*  :secref:`sra-definition` defines the security problem.
*  :secref:`sra-threats` describes the threats and the recommended mitigating actions.
*  :secref:`sra-mitigations` summarizes the mitigations, and where these are implemented.

.. _sra-about:

About this assessment
---------------------

Subject and scope
^^^^^^^^^^^^^^^^^

This SRA analyses the security of the |API| itself, and of the conceptual architectures for storage, not of any specific implementation of the API, or any specific use of the API. It does however, divide implementations into four Deployment Models representing common implentation types, and looks at looks at the different mitigations needed in each Deployment Model. 

In this SRA Sotrage Service means the firmware implementing the |API|. The storage medium refers to the physical sotrage location. 

Risk assessment methodology
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Our risk ratings use an approach derived from NIST Special Publication 800-30 Revision 1: Guide for Conducting Risk Assessments [SP800-30]: for each Threat, we determine its Likelihood and the Impact. Each is evaluated on a 5-level scale, as defined in :numref:`tab-sra-likelihood` and :numref:`tab-sra-impact`.

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

         Partners would complain strongly, and delay or cancel deployment of the feature.

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

Threats are handled starting from the most severe ones. Mitigations will be devised for these Threats one by one (note that a Mitigation may mitigate more Threats, and one Threat may require the deployment of more than one Mitigation to be addressed). Likelihood and Impact will be reassessed assuming that the Mitigations are in place, resulting in a Mitigated Likelihood (this is
the value that usually decreases), a Mitigated Impact (it is less common that this value will decrease), and finally a Mitigated Risk. The Analysis is completed when all the Mitigated Risks are at the chosen residual level or lower, which usually is Low or Very Low.

The Mitigating actions that can be taken are defined in the acronym **CAST**:

*  **Control**: Put in place steps to reduce the Likelihood and/or Impact of a Threat, thereby reducing the risk to an acceptable level.
*  **Accept**: The threat is considered to be of acceptable risk such that a mitigation is not necessary or must be accepted because of other constraint or market needs.
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

The |API| separates the software responsible for providing the security of the data from the caller. The Storage Service calls on firmware that provides low level reads and writes of non-volatile storage medium and the access to any required bus. 
the Storage API is to provide a consistent interface, so that applications do not need to account for the different low-level implementations. 

This analysis does not address the engineering requirements to create a reliable storage medium from the underlying physical storage. It is assumed that the implementation will use the standard techniques, error correcting codes, wear levelling and so on, to ensure the storage is reliable. 

Lifecycle
^^^^^^^^^

:numref:`fig-lifecycle` shows the typical lifecycle of a device.

.. figure:: /figure/lifecycle.*
   :name: fig-lifecycle
   
   Device lifecycle of a system providing storage
   
The Storage Service, and the |API| are active during the operational phase, implemented within the boot-time and run-time software. 

Within a boot session, it is the responsibility of the secure boot firmware to:

 * set up the isolation barriers between partitions
 * provision the firmware implementing the Storage Service
 * provision the credentials for authorizing the storage of data
 * to enable or disable debug facilities.

This SRA only considers threats to the Storage Service in its operational phase. The security of the boot process and of any data provisioning service are not considered in this SRA.

Operation and trust boundaries
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following operational dataflow diagrams include all of the main components in the Storage Service. Presenting the context in which the |API| operates aids understanding of the threats and security mitigations and provides justification for some of the aspects of the API design.

.. figure:: /figure/callers.*
   :name: fig-boundaries
   
   Trust boundaries of a system providing storage

|API| is a C language API. Therefore, any implementation of the API must execute, at least partially, within the context of the caller. When an implementation includes a trust boundary, the mechanism and protocol for communication across the boundary is not defined by this specification.

The operational dataflow diagram is reproduced for each of the deployment models. Although the dataflow itself is common to the models, the placement of trust boundaries is different.

It is helpful to visualize the effect of these differences on the threats against the dataflows.

.. _isolation:

Optional isolation
~~~~~~~~~~~~~~~~~~

Implementations can isolate the Storage Service from the caller and can further isolate multiple calling applications. 
Various technologies can provide protection, for example:

*   Process isolation in an operating system.
*   Partition isolation, either with a virtual machine or a partition manager.
*   Physical separation between execution environments.

The mechanism for identifying callers is beyond the scope of this specification. An implementation that provides caller isolation must document the identification mechanism. An implementation that provides caller isolation must document any implementation-specific extension of the API that enables frontend instances to share data in any form.

In summary, there are two types of implementation:

*   No isolation: there is no security boundary between the caller and the
    Storage Service. For example, a statically or dynamically linked library is an implementation with no isolation.

*   Caller isolation: there are multiple caller instances, with a security boundary between the caller instances among themselves, as well as between the Storage Service and the caller instances. For example, a Storage Service in a multiprocessor environment is an implementation with caller isolation.

Assumptions, constraints, and interacting entities
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This SRA makes the following assumptions about the |API| design:

*   The API does not provide arguments that identify the caller, because they can be spoofed easily, and cannot be relied upon. It is assumed that the implementation of the API can determine the caller identity, where this is required. See :secref:`isolation`.

*   The API does not prevent the use of mitigations that are required by an implementation of the API. See :secref:`remediation`.

*   The :cite-title:`PSM` assumes that at least the code in the :term:`Root of Trust` partitions (:term;`PRoT` and :term:`ARoT`) are verified at boot, and on any update. Therefore, it is assumed that this code is trustworthy. If any malicious code can run in the RoT partitions, it has achieved full control. 

*   For the purposes of this analysis, it is assumed that in deployment models `DM.AUTHORISED` and `DM.SECURE_CHANNEL`, there is no way to access the stored data without going through the authenticated channel. That is, an attack that would expose the physical storage medium is beyond the resources of the attacker. 

*   The analysis only looks at an active attack. However, data is also subject to accidental modification, for example from cosmic radiation causing a bit flip. Therefore standard engineering practice - such as use of error correcting codes - should be taken to protect data.


Goals
^^^^^

:security-goal:`CONFIDENTIALITY`
  The Storage Service will ensure that no data stored can be read, except by the caller that stored it.

:security-goal:`INTEGRITY`
  The Storage Service will ensure that data returned to a caller was the data previously stored by that caller. 

:security-goal:`CURRENCY`
  The Storage Service will ensure that data returned to a caller is the most recent version of the data stored by that caller.

Deployment Models
^^^^^^^^^^^^^^^^^

:deployment-model:`PROTECTED`

  The Storage Service and all physical storage is within the :term:`Platform Root of Trust` (:term:`PRoT`) partition. The :term:`PRoT` partition has sole access to an area of non-volatile storage, thus that storage cannot be accessed by any other partition or any other means. This means that the Storage Service, any driver code, the storage interface and storage medium all reside with the :term:`PRoT` and are protected by the :term:`PRoT`'s isolation mechanisms as shown in :numref:`fig-protected`.
  
  The Storage Service is the arbitrator of access from different applications and manages all data accesses (write, update and deletion). Therefore, the Storage Service is responsible for the `SG.CONFIDENTIALITY`, `SG.INTEGRITY` and `SG.CURRENCY` goals of each caller.
  
  An example of this deployment model is the use of on-chip flash or OTP with an access control mechanism such as a Memory Protection Unit. 

  
  .. figure:: /figure/protected.*
   :name: fig-protected

   Trust boundaries in the Deoployment Model `DM.PROTECTED`
  

:deployment-model:`EXPOSED`

  The :term:`PRoT` partition does not have sole access to the area of non-volatile storage, thus the storage can be read or written by another partition or by other means. This means that the driver code, or the storage interface or the storage medium resides outside the :term:`PRoT` and is accessible to other partitions or by other means, as shown in  as shown in :numref:`fig-exposed`. Therefore, attackers can bypass the Storage Service. 
  
  The Storage Service is the arbitrator of access from different applications and manages those data accesses (write, update and deletion). Therefore, the Storage Service is responsible for the `SG.CONFIDENTIALITY` goal requirements of each caller.
  
  The Storage Service cannot prevent other partitions or other means from reading or writing the storage. Therefore the Storage Service must mitigate the `SG.CONFIDENTIALITY`, `SG.INTEGRITY` and `SG.CURRENCY` goals. 
  
  An example of this deployment model is the use of a file system on a flash chip. 


  .. figure:: /figure/exposed.*
   :name: fig-exposed

   Trust boundaries in the Deoployment Model `DM.EXPOSED`

 
:deployment-model:`AUTHORISED`

  There is a separate isolated partition containing an area of non-volatile storage that can only be accessed in response to an authenticated command and from which all replies include a means for verification of the response, as shown in :numref:`fig-authorised`. The isolation guarantees that there is no access to the storage other than by using the authentication mechanism. 
  
  Therefore, the authentication mechanism must be protected.  In other words, the means of generating the authenticated command and verifying the response must be available only to the Storage Service. This implies that there are confidentiality and integrity goals on any secrets used for this purpose.
  
  The authorisation and verification mechanism provided by the storage controls access to data (reads, writes and modification). This mitigates the `SG.INTEGRITY` and `SG.CURRENCY` goals.
  
  However, the communication between the Storage Service and the storage medium is observable by other partitions and any other means as any data sent in plain text can be observed. Therefore, the Storage Service must mitigate `SG.CONFIDENTIALITY`.  For cryptographic based solutions, this implies that there are confidentiality and integrity goals on any secrets used in cryptographic implementation.
  
  An example of this deployment model is the use of an RPMB memory block. 


  .. figure:: /figure/authorised.*
   :name: fig-authorised

   Trust boundaries in the Deoployment Model `DM.AUTHORISED`

  
:deployment-model:`SECURE_CHANNEL`

  There is a separate isolated partition containing an area of non-volatile storage that can only be accessed in response to an authenticated command and from which all replies include a means for verification of the response, as shown in :numref:`fig-external-secure`.  The isolation guarantees that there is no access to the stored data other than by using the authentication mechanism. 
  
  Therefore, the authentication mechanism must be protected.  In other words, the means of generating the authenticated command and verifying the response must be available only to the Storage Service. This implies that there are confidentiality and integrity goals on any secrets used in cryptographic implementation.
 
  The authorisation and verification mechanism provided by the storage controls access to data (reads, writes and modification). This mitigates `SG.INTEGRITY` and `SG.CURRENCY` goals.
  
  The communication between the Storage Service and the storage medium is protected from observation by other partitions and other means as the data is sent in encrypted form because of the secure channel. This mitigates the `SG.CONFIDENTIALITY` goal. 
  
  However, the secure channel encryption/decryption mechanism must be protected.  In other words, the means of encrypting data transmitted over the secure channel and decrypting data received over the secure channel must be available only to the Storage Service. This implies that there are confidentiality and integrity goals on any secrets used in cryptographic implementation.
  
  An example of this deployment model is the use of a Secure Element, or a secure flash device.


  .. figure:: /figure/external.*
   :name: fig-external-secure
    
   Trust boundaries in the Deoployment Model `DM.SECURE_CHANNEL`

  
Adversarial models
^^^^^^^^^^^^^^^^^^

Adversarial models are descriptions of capabilities that adversaries of systems implementing the |API| can have, grouped into classes. The adversaries are defined in this way to assist with threat modelling an abstract API, which can have different implementations, in systems with a wide range of security sensitivity.

:adversarial-model:`0`
   The Adversary is only capable of accessing data that requires neither physical access to a system containing an implementation of the feature nor the ability to run software on it. This Adversary is intercepting or providing data or requests to the target system via a network or other remote connection.

   For instance, the Adversary can:

   *  Read any input and output to the target through external apparatus.
   *  Provide, forge, replay or modify such inputs and outputs.
   *  Perform timings on the observable operations being done by the target, either in normal operation or as a response to crafted inputs. For example, timing attacks on web servers.

:adversarial-model:`1`
   The Adversary can additionally mount attacks from software running on a target processor implementing the feature. This type of Adversary can run software on the target.

   For instance, the Adversary can:

   *  Attempt software exploitation by running software on the target.
   *  Exploit access to any memory mapped configuration, monitoring, debug register.
   *  Mount any side channel analysis that relying on software-exposed built-in hardware features to perform physical unit and time measurements.
   *  Perform software-induced glitching of resources such as Rowhammer, RASpberry or crashing the CPU by running intensive tasks.

:adversarial-model:`2`
   In addition to the above, the Adversary is capable of mounting hardware attacks and fault injection that does not require breaching the physical envelope of the chips. This type of Adversary has access to a system containing an implementation of the target feature.

   For instance, the Adversary can:

   *  Conduct side-channel analysis that requires measurement equipment. For example, this can utilize leakage sources such as EM emissions, power consumption, photonics emission, or acoustic channels.
   *  Plug malicious hardware into an unmodified system.
   *  Gain access to the internals of the target system and interpose the SoC or memory for the purposes of reading, blocking, replaying, and injecting transactions.
   *  Replace or add chips on the motherboard.
   *  Make simple, reversible modifications, to perform glitching.

:adversarial-model:`3`
   In addition to all the above, the Adversary is capable of performing invasive SoC attacks.

   For instance, the Adversary can:

   *  Decapsulate a chip, via laser or chemical etching, followed by microphotography to reverse engineer the chip.
   *  Use a focussed ion beam microscope to perform gate level modification.

The adversarial models that are in scope for a firmware update process depend on the product requirements. To ensure that the |API| can be used in a wide range of systems, this assessment considers adversarial models `AM.0`, `AM.1`, and `AM.2` to be in-scope.

.. _usability:

.. _sra-threats:

Threats
^^^^^^^

As code in the RoT partitions is assumed to be trustworthy - and any untrustworthy code running in that partition already has complete control of the target - therefore in `AM.1` we only consider threats from malicious actors running in :term:`Non-secure Processing Environment`. 

When considering threats, we transfer the risk of protecting different users within a single partition to the operating system or run time within that partition.

.. threat:: Reading data for a different caller using the API
   :id: SPOOFREAD

   .. deployment model:: `DM.PROTETED` `DM.EXPOSED` `DM.AURTORISED` `DM.SECURE_CHANNEL`  
   .. description::
      In all Deployment Models, an attacker may attempt to read data stored for another caller using the Storage API.
      
      The API does not provide arguments that identify the caller, because they can be spoofed easily, and cannot be relied upon. It is assumed that the implementation of the API can determine the caller identity, where this is required.
       
      The API does not require that the names used by caller for stored data are globally unique, only unique within that caller's namespace. 

   .. mitigations:: :mitigation:`FullyQualifiedNames` 
       
       In order to prevent spoofing, The implementation must always use a fully qualified name to ensure that when a caller requests a file the Storage Sercvice does not return a file of the same name stored by a different caller. 
       
       It must also ensure that if the file with the exact fully qualified name does not exist, then it returns an error. 

   .. security-goal:: :SG:`CONFIDENTIALITY`
   .. adversarial-model:: `AM.1`

   .. unmitigated:: 
      :impact:  VH
      :likelihood: VH

   .. residual:: 
      :impact: VH
      :likelihood: VL

.. threat:: Writing data for a different caller using the API
   :id: SPOOFWRITE

   .. description::
      In all Deployment Models, an attacker may attempt to write data to a file belonging to another caller  using the Storage API, or create a new file in a different caller's namespace.
      
      This threat is the counterpart to `T.SPOOFREAD` except that the attacker tries to write data rather than read. It is therefore subject to the same analysis and can also be mitigated by 'M.FullyQualifiednames`.

   .. mitigations:: `M.FullyQualifiedNames`
      
   .. security-goal:: :SG:`CONFIDENTIALITY`
   .. adversarial-model:: `AM.1`

   .. unmitigated:: 
      :impact: VH
      :likelihood: VH

   .. residual:: 
      :impact: VH
      :likelihood: VL

.. threat:: Eavesdropping
   :id: EAVESDROPPING

   .. description::
      An attacker may be able to access data in transit, either between the caller and the Storage Service, or between the Storage Service and the stoage medium. 
      
      In all deployment modesl by the definition of an isolated partition in the :cite-title:`PSM`, transfer within the partition, and transfers between one  :term:`Secure Partition` and another are isolated from eavesdroppers. Therefore, if the caller is in :term:`Secure Partition`, there is no possibility of an eavesdropper accessng the data. However, if data is sent or returned to a caller in the :term:`Non-secure Processing Environment` (:term:`NSPE`), although the data may be securely ddelivered to the :term:`NSPE`, within that partition it is exposed. As we have noted the duty of separating users in the :term:`NSPE` is TRANSFERRED to the OS.
      
      For deployment model `DM.PROTECTED`, the Storage Service and the physical storage are within the :term:`PRoT` and therefore isolated. 

      In `DM.EXPOSED`, any adversary that can obtain Operating System privileges in the :term:`NSPE` will have access to all the memory and will therefore be able to see all data in transit. The Storage Service must therefore apply `M.Encrypt` to all data before it leaves the :term:`PRoT`.  An attacker that is external to the processor, `AM.2`, will be able to exploit an eavesdropping attack if the bus to which the memory is attached is accessible to external pins, otherwise, the attack is limited to `AM.1`.
      
      In `DM.AUTHORISED`, as the commands and data are sent and received in the clear, albeit with an authorization, anyone on the bus, or with access to intermediate data buffers, can eavesdrop and obtain the messages. Therefore, the implementation must apply `M.Encrypt` to the data before it leaves the :term:`PRoT`. 

      In `DM.SECURE_CHANNEL`, if the external location is accessed without using a Secure Channel, an Adversary with access to the bus (`AM.2`) can trivially eavesdrop on the messages. If the Secure Channel is not rooted in the :term:`PRoT` then any internal adversary (`AM.1`) will be able to eaves drop on traffic leaving the :term:`PRoT` before it is encrypted. However, the stored data does not need to be separately encrypted data beyond the protection provided by the Secure Channel. . 
      
   .. mitigations:: 
      :mitigation:`Encrypt` For `DM.EXPOSED` and `DM.AUTHORISED`, the data at rest must be encrypted. The Storage Service must apply the encryption the data before it leaves the :term:`PRoT` partition. The encryption mechanism chosen must be sufficiently robust. The key used for encryption must be sufficiently protected, that is it must only be available to the Storage Service. 
      
      :mitigation:`:PRoT rooted Secure Channel` For `DM.SECURE_CHANNEL`, communication with the storage medium must be over a well-designed secure channel that is rooted inside the :term:`PRoT`. The private information required to establish the channel must be suitably protected by both parties, the :term:`PRoT` and the storage device.   
      
      :mitigation:`UseSecurepartitions` For all Deployment Models, to ensure that an attacker in the :term:`NSPE` cannot access the data sent by the caller to the Storage Service, or the replies the Storage Service returns to the caller, put all code that needs to use the Storage Service into one or more :term:`Secure Partition`, with one partition per service.


   .. security-goal:: :SG:`CONFIDENTIALITY`

   .. adversarial-model:: `AM.0` `AM.1` `AM.2`

   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a - except for transfer of data to clients in the :term:`NSPE`
      :risk: n/a

   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a
            
   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: VH

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL
      
   .. unmitigated:: DM.AUTHORISED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORISED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.SECURE_CHANNEL
      :impact: VH
      :likelihood: H

   .. residual:: DM.SECURE_CHANNEL
      :impact: VH
      :likelihood: VL


.. threat:: Man in the Middle
   :id: MITM

   .. description:: 
      An attacker can interfere with communication and replace the transmitted data. In this threat we onyl consider attackers between the Storage Service and the storage medium. An attacker interposing between the Caller and the Storage Service is considered under `T.SPOOFREAD` or `T.SPOOFWRITE`. 
      
      For `DM.PROTECTED` the Storage Service and the physical storage are within the :term:`PRoT` partition and therefore isolated. 
     
      For `DM.EXPOSED` any code running in the :term:`NSPE` may be able to access the storage medium and any driver firmware, and therefore act as a man-in-the-middle, by for example persuading the Storage Service to write to one buffer, and the storage medium to read from another. Therefore, the data must be properly encrypted for confidentiality and protected with a MAC, or signature, for integrity. 
      
      For `DM.AUTHORISED` while a man-in the middle can eavesdrop on data in transit, all commands need to be authenticated, and all replies are protected by a MAC. By definition, the Storage medium verifies all commands. Therefore, provided the Storage Service verifies all replies, including checking the status codes returned after it submits a write command, before releasing any data to their caller, the man-in-the-middle cannot change the command or reply without being detected.
      
      For `DM.SECURE_CHANNEL` if the secure channel is set up without authorisation, for example using a simple Diffie-Hellman Key exchange, it would be vulnerable to a man-in-the-middle attack. Given that in this implementation we are not expecting encryption of the data - other than by the channel itself - the attacker would have full access to stored data. 

   .. mitigations:: 
      `M.Encrypt` Encryption ensures that the man in the middle does not know what data is being transferred. It also means they cannot force a specific value to be stored. However, they can still altar the data to be stored, rendering it to be unintelligible on decrytpion.    
    
      :mitigation:`MAC` In `DM.EXPOSED`, applying a Message Authentication Code or a signature or using an authenticated encryption scheme means that the Storage Service can check the integrity of the data when it is read back from the storage area. A man in the middle can still deny service, but we ACCEPT this risk, as it is impossible to prevent code in the :term:`NSPE` simply running a busy loop to deny service. 
      
      :mitigation:`UniqueKeys` For `DM.AUTHORISED` and `DM.SECURE_CHANNEL`, requiring keys used by the storage partition to be unique to each instance ensures that an attacker cannot know the key used on this instance. 
   
      :mitigation:`VerifyReplies` In `DM.AUTHORISED`, commands and replies are authenticated by the storage device. Therefore, the man in the middle should not be able to create a valid reply indicating that the data has been stored when it has not. Provided the Storage Service validates replies, it can be sure that the data it sent was correctly stored, and the data retrieved is the value previously stored.  

      :mitigation:`AuthenticateEndpoints` In `DM.SECURE_CHANNEL`, provided the secure channel set up includes mutual authentication of the Storage Service and ghe storage device, both sides can be sure there is no MITM. This could be because the channel uses a single key known only to both parties. Or if it chooses to use an asymmetric protocol, by means of a signature with each side storing the hash of the other's public key. 
      
      :mitigation:`Replay Protection`  in both `DM.AUTHORISED` and `DM.SECURE_CHANNEL` if the communication protocol includes protection against replay, normally achieved by including a nonce in the construction, it will detect attempts to replay previous commands and reject them. 

   .. security-goal:: :SG:`INTEGRITY`
   .. adversarial-model:: `AM.1` `AM.2`

   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a
      
   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a
      
   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: VH

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORISED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORISED
     :impact: H
     :likelihood: VL

   .. unmitigated:: DM.SECURE_CHANNEL
      :impact: H
      :likelihood: H

   .. residual:: DM.SECURE_CHANNEL
     :impact: H
     :likelihood: VL
     

.. threat:: Bypassing the API, Direct Read Access
   :id: DRA

   .. description:: An attacker might be able to read stored data through a mechanism other than the API.  
   
      In `DM.PROTECTED` due to the isolation of the :term:`PRoT` partition, no attacker should be able to access the stored data. 
      
      In `DM.EXPOSED` all attackers can access the data. We rely on m.Encrypt to ensure that they can only read a ciphertext that they cannot decrypt. 
      
      In `DM.AUTHORISED` the storage medium requires all accesses to be authenticated by a secret key. We assume that this key is known only to the storage device and to the Storage Service. The attacker cannot form valid requests to access data. It can, however, eavesdrop on a legitimate request and replay it later.
      
      In `DM.SECURE_CHANNEL` the storage medium requires all accesses to be over the secure channel We assume that the key required to form the channel is known only to the storage medium and to the Storage Service. The attacker cannot form valid requests to access data. It can, however, eavesdrop on a legitimate request and even if it cannot understand it, it could replay it later.
      
   .. adversarial-model:: `AM.1` `AM.2`

   .. security-goal:: :SG:`CONFIDENTIALITY`

   .. mitigations:: `M.Replay Protection`  in both `DM.AUTHORISED` and `DM.SECURE_CHANNEL` if the communication protocol includes protection against replay, normally achieved by including a nonce in the construction, it will detect attempts to replay previous commands and reject them. 
   
      In `DM.EXPOSED`, `M.Encrypt` ensures that the attacker cannot comprehend the stored data. 
      
      In `DM.AUTHORISED` although an attacker should not be able to form the correct authorization to issue a read command, use of `M.Encrypt` ensures that the attacker cannot comprehend the stored data even if they are able to read it. 


   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a
            
   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a
      
   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: VH

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORISED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORISED
     :impact: H
     :likelihood: VL

   .. unmitigated:: DM.SECURE_CHANNEL
      :impact: H
      :likelihood: H

   .. residual:: DM.SECURE_CHANNEL
     :impact: H
     :likelihood: VL

.. threat:: Bypassing the API, Direct Modification of Data
   :id: DMD

   .. description:: An attacker might be able to modify data stored for another caller.  
   
         In `DM.PROTECTED` due to the isolation of the :term:`PRoT` partition, no attacker should be able to access the stored data. 
         
         In `DM.EXPOSED` we assume that any attacker capable of running code in the :term:`NSPE` can modify the stored data. However, assuming it is encrypted, they cannot know the current value, and given an appropriate encryption scheme, they cannot know how the changed data will be interpreted. However, they can replace the currently stored data with a version stored earlier. 
         
         In `DM.AUTHORISED`, without access to the Authentication key, the attacker cannot form a valid command, so storage medium will reject attempts to modify data. However, the attacker can eavesdrop on a legitimate request and replay it later. Therefore, the communication protocol must include protection against replay. 
         
         In `DM.SECURE_CHANNEL` without access to the Authentication key, the attacker cannot form a valid command, so the storage medium will reject attempts to modify data. However, it can eavesdrop on a legitimate request and replay it later. Therefore, the communication protocol must include protection against replay. 

   .. adversarial-model:: `AM.1` `AM.2`

   .. security-goal:: `SG.INTEGRITY` `SG.CURRENCY`

   .. mitigations:: :mitigation:`AntiRollback` A MAC by itself does not prevent an attacker from replacing one version of a file - or the entire contents of the storage medium - with a previously stored version, as this would include valid signatures. Therefore, in `DM.EXPOSED` to prevent this attack, the Storage Service must keep some authentication data in a location the attacker cannot access. This location could be stored within the :term:`PRoT` Partition `DM.PROTECTED` or in an separate secure enclave `DM.AUTHORISED` or `DM.SECURE_CHANNEL`. The data could be the root of a hash tree, or it could be a counter used with a root key to generate a version specific MAC key. In the case of a counter, some consideration should be given to the expected number of updates that will be made to the data. If we only need to offer rollback protection on firmware updates, there may only be a low number in the lifetime of the product and the counter could be stored in fuse. If we need to ensure the currency of a generic file store - that is regularly updated - the numnber of updates could exhaust any practical number of fuses, and would instead need a 32 bit counter. 

      `M.MAC`  In `DM.EXPOSED`, all attackers can access the data. Therefore, all stored data must be authenticated, using a MAC or signature, which must be verified by the Storage Service within the :term:`PRoT`. 

      
   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a
            
   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a
      
   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: VH

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORISED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORISED
     :impact: H
     :likelihood: VL

   .. unmitigated:: DM.SECURE_CHANNEL
      :impact: H
      :likelihood: H

   .. residual:: DM.SECURE_CHANNEL
     :impact: H
     :likelihood: VL


.. threat:: Physical Replacement of storage
   :id: REPLACE

   .. description:: An attacker might physically replace the storage medium.

   .. adversarial-model:: `AM.3`

   .. security-goal:: `SG.INTEGRITY`

   For `DM.PROTECTED`, as the storage medium is integrated with the :term:`PRoT`, it is not possible to replace the storage. 

   For `DM.EXPOSED`, if the storage medium is integrated with the chip, it is not possible to replace the storage. However, if the data is stored on a separate component, there is the possibility that the entire storage medium will be removed and imaged, and possibly replaced. 

   For `DM.AUTHORISED` and `DM.SECURE_CHANNEL`, it may be possible to replace the storage medium. However, provided that authentication keys are unique per instance and cannot be changed or exposed, and the Storage Service verifies all replies, any attempt to replace the storage medium will be detectable. In the case of DM.AUTHORISED, the new instance will not be able to form the correct responses to commands, in the case of `DM.SECURE_CHANNEL`, the replacement instance will not be able to complete the handshake to set up the secure channel.
      
 
   
   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a
            
   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: n/a
      :risk: n/a
      
   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: VH

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORISED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORISED
     :impact: H
     :likelihood: VL

   .. unmitigated:: DM.SECURE_CHANNEL
      :impact: VH
      :likelihood: H

   .. residual:: DM.SECURE_CHANNEL
     :impact: H
     :likelihood: VL

   .. mitigations:: In `DM.EXPOSED`, `DM.AUTHORISED` and `DM.SECURE_CHANNEL`, using `M.UniqueKeys` enables the Storage Service to detect that the storage medium has been changed, provided that they also employ `M.VerifyReplies`.     
  
   
.. threat:: Glitching during a read
   :id: GLITCH_READ

   .. description:: An attacker with physical access might be able to disrupt the power to cause a misread.
   
   .. adversarial-model:: `AM.3`

   .. security-goal:: `SG.INTEGRITY`   

   In this threat, an attacker with physical access to the deice causes a power or frequency glitch to cause a misread. In particular, it might prevent the Storage Service from performing the verification of replies or causing it to ignore the result of any check. Thus, causing the Storage Service to return an incorrect value to the caller. 
   
   
   
   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: H
            
   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: L
      
   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: H

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORISED
      :impact: VH
      :likelihood: L

   .. residual:: DM.AUTHORISED
     :impact: VH
     :likelihood: VL

   .. unmitigated:: DM.SECURE_CHANNEL
      :impact: VH
      :likelihood: L

   .. residual:: DM.SECURE_CHANNEL
     :impact: VH
     :likelihood: VL
     
   .. mitigations:: :mitigation:`GlitchDetection` in all deployment models, active glitch detection circuits can raise an exception if a glitch is detected, permitting the computing circuitry to take corrective action. 
   

.. threat:: Glitching during a write
   :id: GLITCH_WRITE

   .. description:: An attacker with physical access might be able to disrupt the power to prevent a write from being completed.

   .. adversarial-model:: `AM.3`

   .. security-goal:: `SG.INTEGRITY`
   
   In this threat, an attacker with physical access to the deice causes a power or frequency glitch to cause a write to fail.
   
   In `DM.PROTECTED` this may not be detected.
   
   In `DM.EXPOSED` the invalid write will be detected on a future read provided the system uses `M.MAC`, which it should do due to other threats. 
   
   In `DM.AUTHORISED` and `DM.SECURE_CHANNEL` there is a brief time of check, time of use (TOCTOU), window, where the Storage medium has verified the command but has not written the data to physical storage. In this case, when a subsequent read occurs, the storage medium will apply a new tag to the reply, and the Storage Service will not be aware that it is returned a corrupted read. This risk should be TRANSFERRED to the storage medium which should offer glitch detection.
   
  
   .. unmitigated:: DM.PROTECTED
      :impact: VH
      :likelihood: H
            
   .. residual:: DM.PROTECTED
      :impact: VH
      :likelihood: L
      
   .. unmitigated:: DM.EXPOSED
      :impact: VH
      :likelihood: H

   .. residual:: DM.EXPOSED
      :impact: VH
      :likelihood: VL

   .. unmitigated:: DM.AUTHORISED
      :impact: VH
      :likelihood: H

   .. residual:: DM.AUTHORISED
     :impact: H
     :likelihood: VL

   .. unmitigated:: DM.SECURE_CHANNEL
      :impact: VH
      :likelihood: H

   .. residual:: DM.SECURE_CHANNEL
     :impact: H
     :likelihood: VL

   .. mitigations:: in all deployment models `M.GlitchDetection` can be used to reduce the risk of a successful glitch. 
   
      :mitigation:`ReadAfterWrite`, in all Deployment models, the Storage Service can perform a read operation immediately after a write, while it still retains the original value in memory and compare the two before confirming the write to the caller. 
    
.. _sra-mitigations:

Mitigation Summary
------------------

.. list-table:: Mitigations 
   :name: tab-sra-api-mitigations
   :widths: 1 2 
   :header-rows: 1
   :class: longtable

   *  -  Implementation 
      -  Mitigations

      
   *  -  `DM.PROTECTED`
      -  `M.FullyQualifiedNames`
         `M.GlitchDetection`
         `M.ReadAfterWrite`
         `M.UseSecurepartitions`

   *  -  `DM.EXPOSED`
      -  `M.AntiRollback`
         `M.Encrypt`
         `M.FullyQualifiedNames`
         `M.GlitchDetection`
         `M.MAC`
         `M.ReadAfterWrite`
         `M.UseSecurepartitions`
         
   *  -  `DM.AUTHORISED`
      -  `M.AuthenticateEndpoints`
         `M.FullyQualifiedNames`
         `M.GlitchDetection`
         `M.ReadAfterWrite`
         `M.Replay Protection`
         `M.UniqueKeys`
         `M.UseSecurepartitions`
         `M.VerifyReplies`
         
   *  -  `DM.SECURE_CHANNEL`
      -  `M.AuthenticateEndpoints`
         `M.FullyQualifiedNames`
         `M.GlitchDetection`
         `M.PRoT rooted Secure Channel`
         `M.ReadAfterWrite`
         `M.Replay Protection`
         `M.UniqueKeys` 
         `M.UseSecurepartitions`
         `M.VerifyReplies`
         

In implementation `DM.PROTECTED`, `DM.SECURE_CHANNEL`, the stored data can be implicitly trusted, and therefore it is not required to be encrypted or authenticated. There is also not more secure location to store verification data. However, it is possible for the data to be accidentally corrupted, therefore standard engineering practice to guard against this, for example the use of error correcting codes, should be used. 

In implementation `DM.EXPOSED`, the data can be read or modified by an attacker, therefore the Storage Service must provide confidentiality, integrity, and authenticity by cryptographic means. The keys used to do this must be stored securely. This could be a key derived from the HUK, or separately stored in fuse in a location only readable from the :term:`PRoT`. 

As the attacker can always read and modify the stored data, even if they cannot decrypt the data. They can attempt to subvert a change by resetting the storage medium to a prior state. To detect this, the Storage Service needs to have some means of authenticating that it is reading the most recent state. 

This implies some form of authentication data stored in a location the attacker cannot modify.

In implementation `DM.AUTHORISED`, the data can be observed, even if it cannot be modified. Therefore, data stored does need to be encrypted for confidentiality. However, provided the authentication protocol is strong, and prevents replay, it should not be possible for an attacker to modify the stored data. As the store applies a MAC to each reply, the Storage Service does not need to apply extra integrity. 

In implementation `DM.SECURE_CHANNEL` provided the secure channel is rooted within the :term:`PRoT`. the data transferred cannot be observed ad any modification is detected. Therefore, no further encryption is needed for confidentiality or integrity. 

.. _remediation:

Mitigations to be Provided by the Implementation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. list-table:: Implementation Mitigations 
   :name: tab-sra-api-implementation mitigations
   :widths: 1 2 
   :header-rows: 1
   :class: longtable

   *  -  Mitigations
      -  Description

      
   *  -  `M.AntiRollback`
      -  When using `DM.EXPOSED`, the implementation must provide a mechanism to prevent an attacker from replacing the stored data with version that was valid at a previous date. An attacker can use this attack to reinstate flawed firmware, or to return to a version with a broken credential. 

   *  -  `M.AuthenticateEndpoints`
      -  When using `DM.AUTHORISED` or `DM.SECURE_CHANNEL`, the Storage Service must authenticate the partition on which the data is stored before reading from it or writing to it. 

   *  -  `M.Encrypt`
      -  When using `DM.EXPOSED` or `DM.AUTHORISED`, the Storage Service must encrypt data to be written to storage, and decrypt data read from storage, inside the isolated environment to ensure confidentiality. 

   *  -  `M.FullyQualifiedNames`
      -  In all deployments, the implementation must identify which caller each stored object belongs to and must refer to them internally by the combination of caller identity and name. Otherwise, it might return a stored object to the wrong caller. 

   *  -  `M.MAC`
      -  In `DM.EXPOSED`, the Storage Service must apply an integrity check, a MAC, signature, or authenticated encryption tag, within the Storage Service before it is sent to storage. It must also verify this on every read. 

   *  -  `M.PRoT rooted Secure Channel`
      -  In `DM.SECURE_CHANNEL`, the Storage Service must use a secure channel rooted within the isolated environment to ensure there is no opportunity for eavesdropping. 

   *  -  `M.Replay Protection`
      -  In `DM.AUTHORISED` and `DM.SECURE_CHANNEL` there must be protection against an attacker replaying previous messages

   *  -  `M.UniqueKeys`
      -  In `DM.AUTHORISED` and `DM.SECURE_CHANNEL` the keys used by the storage Service and storage medium must be unique, otherwise there is no mechanism for detecting that the storage medium has been replaced.

   *  -  `M.VerifyReplies`
      -  In `DM.AUTHORISED` and `DM.SECURE_CHANNEL` the Storage Service must verify all replies from the partition that implements storage, to ensure that they do indeed come from the expected partition and no errors are reported. 

Mitigations to be Provided by the caller
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. -residual:

.. list-table:: caller Mitigations 
   :name: tab-sra-api-caller mitigations
   :widths: 1 2 
   :header-rows: 1
   :class: longtable
   
   
   *  -  Mitigations
      -  Description

   *  -  `M.UseSecurepartitions`
      -  In all deployments, if the caller wants to be certain that there is no chance of eavesdropping or impersonation, they should make use of caller isolation, with each caller in its own isolated partition. 

