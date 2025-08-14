from mitreattack.stix20 import MitreAttackData
import json


def main():
    mitre_attack_data = MitreAttackData("../data/enterprise-attack.json")

    # get all techniques and subtechniques
    techniques = mitre_attack_data.get_techniques()
    subtechniques = mitre_attack_data.get_subtechniques()

    # Create a mapping of techniques with their subtechniques
    techniques_with_subtechniques = {}
    
    # First, process all techniques
    for technique in techniques:
        # Extract technique ID from external references
        technique_id = None
        for ref in getattr(technique, 'external_references', []):
            if getattr(ref, 'source_name', '') == 'mitre-attack':
                technique_id = getattr(ref, 'external_id', '')
                break
        
        if technique_id:
            techniques_with_subtechniques[technique_id] = {
                "id": technique.id,
                "name": technique.name,
                "technique_id": technique_id,
                "description": getattr(technique, 'description', 'No description available'),
                "subtechniques": []
            }
    
    # Now process all subtechniques and match them to their parent techniques
    for subtechnique in subtechniques:
        # Extract subtechnique ID from external references
        subtechnique_id = None
        for ref in getattr(subtechnique, 'external_references', []):
            if getattr(ref, 'source_name', '') == 'mitre-attack':
                subtechnique_id = getattr(ref, 'external_id', '')
                break
        
        if subtechnique_id and '.' in subtechnique_id:
            # Extract parent technique ID (e.g., T1234 from T1234.001)
            parent_technique_id = subtechnique_id.split('.')[0]
            
            if parent_technique_id in techniques_with_subtechniques:
                sub_data = {
                    "id": subtechnique.id,
                    "name": subtechnique.name,
                    "technique_id": subtechnique_id,
                    "description": getattr(subtechnique, 'description', 'No description available')
                }
                techniques_with_subtechniques[parent_technique_id]["subtechniques"].append(sub_data)

    # Filter to only include techniques that have subtechniques
    techniques_with_subs_only = {k: v for k, v in techniques_with_subtechniques.items() if v["subtechniques"]}

    # Output as formatted JSON
    print(json.dumps(techniques_with_subs_only, indent=2))


if __name__ == "__main__":
    main()
