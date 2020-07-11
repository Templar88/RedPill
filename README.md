# RedPill

RedPill is a simulation written in c# that computes the probability of a threat actor breaching an organization. The actions of the threat actors match the distribution of known bad actor and/or malicious software actions as put forward by the Mitre ATT&CK Framework. The simulated organization can mitigate or detect the actors by employing mitigations or monitorign data sources as laid out by the same framework.

## Usage

To set mitigations or monitored data sources for the various environment types modify the appropriate csv:
e.g. mitigations in the DMZ would be set in Data\mitigations\_DMZ.

Set overall simulation details in Config\SimConfig\_Default. 

To Start simulation run the following in the top level directory:
```powershell
dotnet run -File Config\SimConfig_Default

```

## Contributing
Please message if interested in contributing. 

## License
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
