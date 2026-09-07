# Attackers and Attack Surfaces Overview

This document summarizes the actors around a secure element, their possible
goals when they become adversaries, and the attack surfaces they can access.

## Actors

### Foundries

Normal role:
- manufacture the silicon;
- deliver the physical component that becomes the secure element substrate.

Accessible attack surfaces:
- the interface between the kernel and the hardware;
- more generally, any root assumption tied to the actual behavior of the
  silicon.

Possible malicious goals:
- steal secrets manipulated by service providers;
- weaken or bypass the integrity guarantees offered by the hardware;
- introduce undocumented behavior below the software level.

Note:
- this surface is identified but declared out of scope in Chapter 2 of the
  manual.

### Providers

Normal role:
- activate the platform;
- deploy the base software stack;
- implement and package the secure-element kernel;
- establish the initial trust base.

Accessible attack surfaces:
- internal kernel interfaces;
- initial provisioning mechanisms;
- the kernel-to-hardware boundary.

Possible malicious goals:
- weaken isolation between services;
- access application secrets;
- bypass the security controls they are expected to enforce.

Note:
- they are not the main attacker category modeled in Chapter 2, but they are
  part of the trust assumptions.

### Issuers

Normal role:
- distribute the object or device;
- personalize and configure the base applications;
- manage operational enrollment.

Accessible attack surfaces:
- administrative commands;
- personalization and configuration chains;
- authorized deployment channels.

Possible malicious goals:
- deploy unauthorized configurations;
- install or authorize unexpected services;
- misuse administrative mechanisms.

Note:
- their role mainly appears in authority boundaries and trust assumptions.

### Service Providers

Normal role:
- deploy dedicated applications;
- inject service-specific secrets and data;
- operate during the device lifetime, including post-issuance and OTA phases.

Accessible attack surfaces:
- the kernel access interface;
- the service-sharing or inter-service invocation interface, if such an
  interface exists;
- lifecycle commands exposed to them.

Possible malicious goals:
- steal the secrets of other service providers;
- compromise the integrity of their data or execution;
- bypass isolation;
- obtain privileges beyond those granted to them.

Note:
- this category becomes central as soon as multiple Rustlets or distinct
  applications coexist inside the secure element.

### End Users

Normal role:
- use the device;
- consume the exposed services;
- may trigger service or application installation requests.

Accessible attack surfaces:
- the APDU interface;
- the hardware interface exposed to the outside world.

Possible malicious goals:
- steal secrets manipulated by service providers;
- undermine the integrity of those secrets or their associated processing;
- trigger illegitimate or malformed command sequences.

## Main Attack Surfaces

### 1. End-user-side surface

Main actor:
- the end user, or an adversary positioned on the user side.

Goals:
- steal secrets;
- undermine the integrity of service-provider data.

Surfaces:
- APDU;
- exposed hardware.

Examples of points to monitor:
- APDU parser;
- dispatch logic;
- command authentication controls;
- secure channel;
- robustness against malformed sequences, replay, relay, and context confusion.

### 2. Service-provider-side surface

Main actor:
- a hostile service provider with respect to other service providers.

Goals:
- steal the secrets of other services;
- violate isolation;
- obtain privileged effects through the kernel.

Surfaces:
- the kernel access interface;
- the service-sharing interface, if one exists.

Examples of points to monitor:
- privileged-services API;
- rights enforcement;
- kernel mediation;
- memory and persistence isolation;
- inter-service invocation;
- shared objects and handles.

### 3. Foundry-side surface

Main actor:
- a foundry, or an adversary positioned below the software stack.

Goals:
- steal the secrets of service providers;
- weaken the root guarantees of the platform.

Surfaces:
- the kernel-to-hardware interface.

Status:
- out of scope in Chapter 2 of the manual.

## Short Reading

The project should currently prioritize the APDU surface, because it is the
main surface effectively exposed today. In the medium term, isolation between
Rustlets and the definition of the kernel service interface will become a
second major surface, potentially critical as soon as multiple distinct
service providers coexist. The foundry-side surface remains fundamental for the
chain of trust, but it is explicitly excluded from the scope of Chapter 2.
