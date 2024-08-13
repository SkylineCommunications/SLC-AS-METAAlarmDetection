/*
****************************************************************************
*  Copyright (c) 2024,  Skyline Communications NV  All Rights Reserved.    *
****************************************************************************

By using this script, you expressly agree with the usage terms and
conditions set out below.
This script and all related materials are protected by copyrights and
other intellectual property rights that exclusively belong
to Skyline Communications.

A user license granted for this script is strictly for personal use only.
This script may not be used in any way by anyone without the prior
written consent of Skyline Communications. Any sublicensing of this
script is forbidden.

Any modifications to this script by the user are only allowed for
personal use and within the intended purpose of the script,
and will remain the sole responsibility of the user.
Skyline Communications will not be responsible for any damages or
malfunctions whatsoever of the script resulting from a modification
or adaptation by the user.

The content of this script is confidential information.
The user hereby agrees to keep this confidential information strictly
secret and confidential and not to disclose or reveal it, in whole
or in part, directly or indirectly to any person, entity, organization
or administration without the prior written consent of
Skyline Communications.

Any inquiries can be addressed to:

	Skyline Communications NV
	Ambachtenstraat 33
	B-8870 Izegem
	Belgium
	Tel.	: +32 51 31 35 69
	Fax.	: +32 51 31 01 29
	E-mail	: info@skyline.be
	Web		: www.skyline.be
	Contact	: Ben Vandenberghe

****************************************************************************
Revision History:

DATE		VERSION		AUTHOR			COMMENTS

12/08/2024	1.0.0.1		SCU, Skyline	Initial version
****************************************************************************
*/

namespace METAAlarmDetection_1
{
	using System;
	using System.Collections.Generic;
	using System.Linq;
	using Skyline.DataMiner.Automation;
	using Skyline.DataMiner.Core.InterAppCalls.Common.CallBulk;
	using Skyline.DataMiner.Core.InterAppCalls.Common.CallSingle;
	using Skyline.DataMiner.Net.Helper;
	using Skyline.DataMiner.Net.Messages;

	public enum SeveritiesTypes
	{
		Critical = 1,
		Major = 2,
		Minor = 3,
		Warning = 4,
		Normal = 5,
		High = 6,
		Low = 7,
		Escalated = 8,
		Dropped = 9,
		NewAlarm = 10,
		Cleared = 11,
		Open = 12,
		Information = 13,
		Mobile_Gateway = 14,
		Service_Monitor = 15,
		DataMiner_System = 16,
		Timeout = 17,
		Not_Assigned = 18,
		Acknowledged = 19,
		Resolved = 20,
		Unresolved = 21,
		Comment_Added = 22,
		Correlation_Engine = 23,
		Error = 24,
		Mask = 25,
		Automation_Engine = 26,
		Unmask = 27,
		Notice = 28,
		WatchDog = 29,
		External = 30,
		Dropped_from_Critical = 31,
		Dropped_from_Major = 32,
		Dropped_from_Minor = 33,
		Dropped_from_Warning = 34,
		Escalated_from_Warning = 35,
		Escalated_from_Minor = 36,
		Escalated_from_Major = 37,
		Flipped = 38,
		Systemdisplay = 39,
		Service_impact_changed = 40,
		Value_changed = 41,
		Name_changed = 42,
		RCA_level_changed = 43,
		Element = 44,
		Service = 45,
		View = 46,
		Read_only = 47,
		Read_write = 48,
		Alarm = 49,
		Properties_changed = 50,
		Protocol = 51,
		Internal = 52,
		Threshold_changed = 53,
		Clearable = 54,
	}

	/// <summary>
	/// Represents a DataMiner Automation script.
	/// </summary>
	public class Script
	{
		/// <summary>
		/// The script entry point.
		/// </summary>
		/// <param name="engine">Link with SLAutomation process.</param>
		public static void Run(IEngine engine)
		{
			try
			{
				RunSafe(engine);
			}
			catch (ScriptAbortException)
			{
				// Catch normal abort exceptions (engine.ExitFail or engine.ExitSuccess)
				throw; // Comment if it should be treated as a normal exit of the script.
			}
			catch (ScriptForceAbortException)
			{
				// Catch forced abort exceptions, caused via external maintenance messages.
				throw;
			}
			catch (ScriptTimeoutException)
			{
				// Catch timeout exceptions for when a script has been running for too long.
				throw;
			}
			catch (InteractiveUserDetachedException)
			{
				// Catch a user detaching from the interactive script by closing the window.
				// Only applicable for interactive scripts, can be removed for non-interactive scripts.
				throw;
			}
			catch (Exception e)
			{
				engine.ExitFail("Run|Something went wrong: " + e);
			}
		}

		private static void RunSafe(IEngine engine)
		{
			engine.Timeout = new TimeSpan(0, 15, 0);

			ScriptParam paramCorrelationAlarmInfo = engine.GetScriptParam(65006);

			if (paramCorrelationAlarmInfo == null)
			{
				return;
			}

			string sAlarmInfo = paramCorrelationAlarmInfo.Value;

			if (!sAlarmInfo.Contains("|"))
			{
				return;
			}

			string[] asAlarmInfo = sAlarmInfo.Split('|');

			int dmaID = Convert.ToInt32(asAlarmInfo[1]);
			int elementID = Convert.ToInt32(asAlarmInfo[2]);
			int parameterID = Convert.ToInt32(asAlarmInfo[3]);
			string parameterIdx = asAlarmInfo[4];
			string severity = GetSeverityType(Convert.ToInt32(asAlarmInfo[7]));
			string type = GetSeverityType(Convert.ToInt32(asAlarmInfo[8]));
			string alarmValue = asAlarmInfo[10];
			DateTime alarmTime = DateTime.Parse(asAlarmInfo[11]);

			Element sourceElement = engine.FindElement(dmaID, elementID);
			if (sourceElement == null)
			{
				return;
			}

			GetProtocolInformationMessage slnetMessage = new GetProtocolInformationMessage(sourceElement.ProtocolName, $"Protocol_Default:{sourceElement.ProtocolVersion}");
			DMSMessage[] dmsMessage = engine.SendSLNetMessage(slnetMessage);
			GetProtocolInformationResponseMessage response = (GetProtocolInformationResponseMessage)dmsMessage[0];

			string parameterName = response.Params.Where(param => param.ID.Equals(parameterID)).Select(param => param.Description).FirstOrDefault();

			ScriptDummy whatsappElement = engine.GetDummy(2);
			ElementFilter filter = new ElementFilter
			{
				NameFilter = whatsappElement.ElementName,
				ProtocolName = whatsappElement.ProtocolName,
				ProtocolVersion = whatsappElement.ProtocolVersion,
			};
			Element whatsAppElement = engine.FindElements(filter).FirstOrDefault();
			if (whatsAppElement == null)
			{
				engine.Log("No WhatsApp element found.");
				return;
			}

			string alarmParameter = parameterIdx.IsNotNullOrEmpty() ? $"{parameterName} - {parameterIdx}" : parameterName;

			// Create the message
			AlarmMessage message = new AlarmMessage
			{
				Element = sourceElement.ElementName,
				Parameter = alarmParameter,
				Value = alarmValue,
				Severity = severity,
				Time = alarmTime.ToString(),
				Type = type,
			};

			SendMessages(message, whatsAppElement.DmaId, whatsAppElement.ElementId);
		}

		private static string GetSeverityType(int severityValue)
		{
			if (!Enum.IsDefined(typeof(SeveritiesTypes), severityValue))
			{
				return "Unknown";
			}

			var severity = ((SeveritiesTypes)Enum.ToObject(typeof(SeveritiesTypes), severityValue)).ToString();
			return severity.Contains('_') ? severity.Replace('_', ' ') : severity;
		}

		private static void SendMessages(AlarmMessage message, int dmaId, int elementId)
		{
			// Prepare necessary mappings
			List<Type> knownTypes = new List<Type> { typeof(AlarmMessage) };

			// Create new IInterAppCall
			IInterAppCall myCommands = InterAppCallFactory.CreateNew();

			// Add the message to the InterApp call
			myCommands.Messages.Add(message);

			// Send the InterApp call to the destinationElement
			// Parameter 9000000 (9 million) is the default parameter for InterApp call messages
			myCommands.Send(Engine.SLNetRaw, dmaId, elementId, 9000000, knownTypes);
		}
	}

	public class AlarmMessage : Message
	{
		public string Element { get; set; }

		public string Parameter { get; set; }

		public string Value { get; set; }

		public string Severity { get; set; }

		public string Time { get; set; }

		public string Type { get; set; }
	}
}
