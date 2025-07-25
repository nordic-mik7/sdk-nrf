.. _bootloader:

|NSIB|
######

.. contents::
   :local:
   :depth: 2

The |NSIB| (NSIB), previously also known as *B0* or ``b0``, is a secure bootloader built and maintained by Nordic Semiconductor.
It is specifically tailored for the :ref:`immutable bootloader architecture <immutable_bootloader>` of a secure boot chain.
It can verify and boot a second-stage bootloader or application while providing a persistent and reliable :ref:`Root of Trust (RoT) <ug_bootloader_chain_of_trust>`.

See :ref:`ug_bootloader` for more information about the full bootloader chain.

.. note::

   Currently, the NSIB does not support performing firmware updates over the SMP transport.
   If the application using the NSIB requires SMP-based firmware updates, such as Bluetooth® LE DFU, :ref:`include MCUboot as a second-stage bootloader <ug_bootloader_adding_sysbuild_upgradable>`.

.. _bootloader_rot:

Requirements
************

The NSIB supports the following development kits:

.. table-from-sample-yaml::

The NSIB can only boot images that enable the firmware information module, see the :ref:`doc_fw_info` module.

Overview
********

The NSIB implements a simple and reliable :ref:`Root of Trust (RoT) <ug_bootloader_chain_of_trust>` for a secure boot chain, as described in the :ref:`immutable_bootloader` conceptual documentation.

For locking the flash memory, the NSIB uses the :ref:`fprotect_readme` driver.

For the signature verification, to save space, NSIB only stores the hashes of the provisioned keys and compares only the hashes of these keys.
The next image has metadata containing the full public key that corresponds to the private key used to sign the firmware.
This public key is checked against the provisioned hashes of public keys to determine if the image is valid.
All public key hashes at lower indices than the matching hash are permanently invalidated at this point.
You can use this mechanism to decommission compromised keys.

.. note::
   Make sure you provide NSIB with your own keys, as described in :ref:`bootloader_provisioning`, before you program it.

At the end of the RoT establishment, the NSIB also shares some of its functionality through an external API (``EXT_API``).
For more information on the process, see :ref:`doc_bl_crypto`.
For more information on ``EXT_API``, see :ref:`doc_fw_info_ext_api`.

.. _bootloader_provisioning:

Provisioning
============

The public key hashes are not compiled with the source code of the NSIB.
Instead, they must be written to the device in a process called *provisioning*.

The hashes are automatically generated by the build system based on the specified private key and the additional public keys.

By default, the hashes are placed directly into the NSIB HEX file and then automatically provisioned when the HEX file is programmed to the device.

However, in a more realistic manufacturing process, you can program the NSIB HEX file and the HEX file containing the hashes separately, using the Python scripts located in the :file:`scripts/bootloader` folder.

In either case, the NSIB accesses the provisioned data at run time using the :ref:`doc_bl_storage` library.

.. _bootloader_provisioning_otp:

OTP regions
-----------

The one-time programmable (OTP) region is a special region of the *User Information Configuration Registers* (UICR) that only allows flash memory writes in half-word lengths, and *only* when the target half-word has the value of ``0xFFFF``.

On products that support an OTP region, such as the nRF91 Series and nRF5340, the provisioned data is held in the OTP region instead of the internal flash memory.

Because of these design constraints, the following limitations apply:

* The public key hash must not contain half-words with the value ``0xFFFF``, as such hashes cannot be guaranteed to be immutable when placed in the OTP region.
  If any such hashes are provisioned, the NSIB will refuse to boot.
  If your public key hash is found to contain this value, :ref:`it must be regenerated<ug_fw_update_keys>`.

* Provisioned data cannot be written more than once to the target device.
  When programming images that contain flash memory content in the UICR region, such as the NSIB image, the UICR must first be erased.

.. note::
   On the nRF91 Series and nRF5340 devices, the UICR can only be erased by erasing the entire flash memory.

For information how to erase the entire flash memory when flashing, see :ref:`programming`.

.. _bootloader_flash_layout:

Flash memory layout
===================

The flash memory layout is defined by the :file:`samples/bootloader/pm.yml` file, which establishes four main partitions:

* *B0* - The NSIB image.
* *Provision* - The provisioned data.
* *S0* - Slot 0.
* *S1* - Slot 1.

The default location for placing the next image in the boot chain is *S0*.
This would result, for example, in a flash memory layout like the following, when using the ``nrf52840dk/nrf52840`` board target:

.. figure:: ../../doc/nrf/images/b0_flash_layout.svg
   :alt: B0 flash memory layout

   B0 flash memory layout

.. note::
   When the *Provision* area is in the OTP region, it will not appear in the flash memory layout.
   See :ref:`bootloader_provisioning_otp` for more information.

.. _bootloader_pre_signed_variants:

Pre-signed variants
-------------------

When two slots are present, two images must be built.
One that is executable from slot 0, and the other one from slot 1.
Building the image for slot 1 is done by enabling the :kconfig:option:`SB_CONFIG_SECURE_BOOT_BUILD_S1_VARIANT_IMAGE` option.

When the image for the next stage in the boot chain is upgraded, the new image is written to the slot with the oldest image version.
See :ref:`bootloader_monotonic_counter` for more information about versioning.

If this image is faulty and cannot be booted, the other partition will always hold a working image that is booted instead.

When using the ``nrf52840dk/nrf52840`` board target, this would produce a flash memory layout like the following:

.. figure:: ../../doc/nrf/images/b0_mcuboot_flash_layout.svg
   :alt: B0 flash memory layout with MCUboot

   B0 flash memory layout with MCUboot

Configuration
*************

|config|

.. _bootloader_signature_keys:

Signature keys
==============

The ECDSA-P256 key type is supported for validating the next image in the boot chain.
See :ref:`bootloader_signature_keys_guide` for more information.

Monotonic counter
=================

.. include:: ../../doc/nrf/app_dev/bootloaders_dfu/mcuboot_nsib/bootloader_downgrade_protection.rst
   :start-after: bootloader_monotonic_counter_start
   :end-before: bootloader_monotonic_counter_end

.. include:: ../../doc/nrf/app_dev/bootloaders_dfu/mcuboot_nsib/bootloader_downgrade_protection.rst
   :start-after: bootloader_monotonic_counter_nsib_start
   :end-before: bootloader_monotonic_counter_nsib_end

.. _bootloader_build_and_run:

Building and running
********************

.. |sample path| replace:: :file:`samples/bootloader`

.. include:: /includes/build_and_run.txt

.. caution::
   |NSIB| should be included as an image in a project using sysbuild, rather than being built stand-alone.
   While it is technically possible to build the NSIB by itself and merge it into other application images, this process is not supported.
   To reduce the development time and potential issues with this route, let the existing |NCS| infrastructure for sysbuild handle the integration.

   The NSIB is automatically added as an image when the :kconfig:option:`SB_CONFIG_SECURE_BOOT_APPCORE` sysbuild Kconfig option is set.

For building and running the NSIB with an application, see :ref:`ug_bootloader_adding_sysbuild_immutable`.

Dependencies
************

The following |NCS| libraries are used:

* :ref:`partition_manager`
* :ref:`doc_fw_info`
* :ref:`fprotect_readme`
* :ref:`doc_bl_crypto`
* :ref:`doc_bl_validation`
* :ref:`doc_bl_storage`

It uses the following `sdk-nrfxlib`_ libraries:

* :ref:`nrfxlib:nrf_cc310_bl_readme`
* :ref:`nrfxlib:nrf_oberon_readme`
