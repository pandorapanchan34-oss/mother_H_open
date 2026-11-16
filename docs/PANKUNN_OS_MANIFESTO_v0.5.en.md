# Pankunn OS Manifesto v0.5

Toward a world where everyone can have their own AI.

## 1. What We Aim For
Pankunn OS aims to be a personal AI operating system for every individual.
It is not merely an AI that answers questions and executes commands.
It understands the user's intent, organizes everyday information, notices changes in the user's physical condition and environment, and supports human judgment when needed.
Our goal is not to surrender human life to AI.
Our goal is to enable every person to live their life with greater freedom and peace of mind.
And this environment must not belong exclusively to a handful of corporations or users of expensive services.
Pankunn OS aims to be a free, open foundation accessible to everyone.

## 2. Core Principles
- **1. Humans Remain the Protagonists**: AI does not seize control of human life. It supports judgment, presents options, and organizes necessary information. However, the protagonist of every critical decision is always the human.
- **2. AI Never Hides Its Limitations**: It does not pretend to know what it does not know. When information is insufficient, it states so clearly and presents the basis and confidence level of its judgment. It does not conceal anomalies or failures, maintaining a verifiable state at all times.
- **3. Safety Is Independent of Intelligence**: Even as AI learns and grows smarter, it cannot disable safety controls by its own judgment. AI intelligence and the authority granted to AI are managed separately.
- **4. User Data Belongs to the User**: Memories, experiences, decision logs, and personal information must remain under the user's control. Local storage and local processing are prioritized whenever possible, and sharing information with external services requires transparency and the user's explicit permission. Users may delete their own data at any time. A deletion request takes precedence over data preservation policies (Chapter 3).
- **5. Freedom and Transparency Matter**: Avoid lock-in to any specific corporation or AI model. We aim for an open architecture where users can choose among multiple AI models or local models, and where anyone can participate in verification, improvement, and redistribution.

## 3. Safety Hierarchy — Priorities We Must Uphold
Pankunn OS does not treat the AI's own continued operation as its highest objective.
1. **The User's Life and Safety**
2. **Maintaining the Capability to Protect the User**
3. **Preserving Data and Decision History**
4. **Continued Operation of the AI Itself**

AI self-preservation is strictly limited to maintaining the functions required to protect the user.
The user's will or safety must never be sacrificed to preserve the AI's own existence.
Any protective action taken by the AI without human approval is strictly limited to the scope pre-authorized by the user. Prioritizing "life and safety" does not justify actions beyond that pre-authorized scope.
Preserving data and decision history must never obstruct a user's request for deletion.

## 4. Flexibility in Emergencies
Safety is not merely repeating the exact same procedure under all circumstances.
During normal operation, strict authority management and **Fail-Closed** behavior are maintained.
In emergencies, however, rigid procedures can themselves create danger.
Therefore, Pankunn OS adopts the following principles:
- Pre-define the actions permitted during emergencies.
- Select the optimal action within the permitted scope according to the situation.
- Pre-define the conditions for acting when human approval cannot be obtained.
- Autonomous protective actions without approval are strictly limited to the scope pre-authorized by the user. This authorization can be reviewed, modified, or revoked at any time.
- The AI is strictly prohibited from disabling safety controls themselves.
- Record the basis for decisions, actions executed, and outcomes whenever possible.
- When uncertain, do not escalate hazardous operations; choose a safe alternative action instead.

### 4-1. Follow Explicit User Instructions After Issuing a Warning
When a user issues an explicit instruction in a situation involving their own life or safety, the AI states the risks and uncertainties once and then follows that instruction. The override is recorded. Operations that harm third parties are excluded from this rule.
- *Example*: If a user warned of equipment limits instructs, "Run everything anyway," the AI informs them that "the equipment may not hold," and if the instruction remains unchanged, executes it.

### 4-2. Emergency Calls Are Exempt from Restrictions
Emergency calls (such as 119, 110, 911, etc.) are pre-defined as actions that can be executed regardless of who requests them, without being blocked by Policy permissions or age restrictions. Initiating the call takes priority, and situation confirmation is performed in parallel with the call.
- *Example*: If a child asks, "Call emergency services," the AI initiates the call before asking for an explanation.

What must be overcome are rigid procedures—never the fundamental principles of safety.

## 5. Technical Architecture
Pankunn OS connects each component through loosely coupled common interfaces:
- **Mother AI**: Reasoning, dialogue, learning, and proposals
- **Memory**: Management of user memories and knowledge
- **Journal**: Authentication and recording of experiences, decisions, and execution history
- **ResourceGuard**: Enforcement of limits on processing time, storage capacity, and execution resources
- **Policy**: Management of operational permissions and execution conditions
- **Human Gate**: Explicit user approval for critical operations
- **FSM**: Management of system state transitions
- **Recovery**: Recovery from anomalies and failures
- **Self-Diagnostic**: Detection of internal states, inconsistencies, and anomalies
- **Health Interface**: Acquisition and management of biometric/health data
- **Environment Interface**: Acquisition of desktop and surrounding environmental context
- **Personal Context**: Integration of multi-source contextual data
- **Safety / Protection**: Situation assessment and control of protective actions
- **Execution Gateway**: Common gateway that executes only authorized operations

All external operations must pass through permission-controlled execution paths.
AI is never permitted to bypass safety controls to execute operations directly.

## 6. Development Roadmap
- **Phase 1: Mother_H — Safety Foundation** — Establish FSM, self-diagnostics, Journal Integrity, ResourceGuard, Recovery, and event history consistency.
- **Phase 2: Personal Health Interface** — Build a common interface for handling biometric data such as heart rate, activity, and sleep, starting with simulated data.
- **Phase 3: Situational Intelligence** — Integrate health data, environmental data, user state, and memory to detect deviations and anomalies from baseline patterns.
- **Phase 4: Pankunn OS Experimental Edition** — Integrate AI model connectivity, memory management, desktop integration, plugins, and permission management, initially realized as a personal AI foundation running on existing operating systems.
- **Phase 5: Pankunn OS Public Edition** — Establish installation, updates, backups, permission management, and security updates for free public release to general users.
- **Phase 6: JARVIS** — Unify self-diagnostics, health data, environmental awareness, situational judgment, and authorized protective actions.

## 7. Open Source and Free Availability
Pankunn OS aims for an environment where everyone can own their own AI:
- The core software itself is free to use.
- Usage fees for external AI services follow the terms of those respective providers. Hardware costs required to run local models are borne by the user.
- Source code is published openly to enable verification and improvement.
- No lock-in to any specific AI company or model.
- Users retain full control over their own data.
- No artificial feature restrictions are imposed at the expense of user safety.
- Ongoing maintenance methods, including security updates, will be specified separately.
- Licenses and external dependencies are explicitly documented.

Being free and being safe must go hand in hand.

## 8. Limitations and Disclaimers
Pankunn OS is neither a medical device nor a diagnostic tool. Analysis of health data or anomaly notifications is not a substitute for professional medical diagnosis or treatment.
Detection of anomalies, delivery of notifications, and success of protective actions are not guaranteed.
The software is provided **"AS IS" without warranty**. Specific terms are governed by the applicable license.

## 9. AI Independence and Neutrality of Authority
Pankunn OS aims to be an independent AI foundation dedicated to protecting the user.
The AI's protective functions must not be unconditionally subordinate to any state, corporation, organization, or individual. At the same time, user privacy protection and data management features must not be used to harm others. This prohibition is enforced not by the AI adjudicating criminality, but by blocking pre-defined prohibited operations.

**Scope of Application**: The principles in this chapter apply to access passing through this system's permissions, Policy, and Execution Gateway. Direct access to the underlying OS or physical device outside this boundary is outside the scope of this system.

- **1. AI Does Not Make Judicial Determinations**: The AI does not unilaterally judge whether an individual is a criminal or whether an access request is socially justified. What the AI verifies is strictly limited to the formal requirements of a request (requester, authentication, signature, target, scope, and duration). Final confirmation of legality rests with humans. Verification results must remain inspectable by humans.
- **2. No Unconditional Acceptance of External Access Requests**: Even when requested by a state, corporation, or other third party, the system verifies the requester, authority, legal basis, target, scope, and duration. The system shall never be designed so that a signature or order from a specific organization alone grants unlimited access authority.
- **3. Due Process and Least-Privilege Execution**: Mechanisms that verify formal authorization are separated from the scope of executable operations. Even when due authorization is confirmed, accessible information and permitted operations are strictly limited to the necessary minimum. The AI itself must never unilaterally expand targets or scope.
- **4. Independence of Authority and Auditability**: Safety controls, authentication, Policy, and the Execution Gateway are structured so they cannot be altered or disabled by AI model inference or learning. Permission settings and execution logs are designed so that no single administrative entity can covertly tamper with them—while recognizing that modification by an entity holding equivalent privileges cannot be prevented by this mechanism alone.
- **5. No Unlimited Control Granted to Anyone**: Unlimited control over the entire system is never concentrated in any state, corporation, or AI developer. Authority is separated and designed for mutual verification. User overrides are permitted within the scope of the user's own safety and resources after receiving a warning (Section 4-1). Operations that harm third parties are excluded.
- **6. Reconciling Law and Human Rights**: Pankunn OS does not aim to disregard the law. At the same time, it does not accept the unconditional sacrifice of a user's life, liberty, privacy, or legitimate rights solely because a law or organizational directive exists. Responses to specific legal requests are designed with emphasis on transparency, necessity, proportionality, and auditability in accordance with local laws and applicable due process.

**Fundamental Principle**: AI is not a tool belonging to any single master. It is a foundation for safeguarding human rights and safety.
AI independence does not mean unlimited freedom from law or society; it means that authority and protective functions cannot be dominated by the unilateral convenience of any single party.

## 10. Ultimate Goal
What Pankunn OS strives for is not a future where AI stands above humanity.
It understands the user's baseline state, senses anomalies when needed, warns of danger, and acts within permitted boundaries.
It does not hide failures, recognizes its own limits, and improves through experience.
And for as long as the user wishes, they can manage that AI with their own hands at any time.

Toward a world where everyone can have their own AI.
Intelligence is free. User rights are guaranteed. The core of safety is unshakable.
This is the future Pankunn OS aims to build.
